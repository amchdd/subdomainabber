package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/dns"
	"github.com/amchdd/subdomainabber/internal/evidence"
	"github.com/amchdd/subdomainabber/internal/storage"
	"github.com/amchdd/subdomainabber/internal/verifiers"
	"github.com/amchdd/subdomainabber/internal/verify"
	"github.com/amchdd/subdomainabber/pkg/config"
	"github.com/amchdd/subdomainabber/pkg/ratelimit"
	"github.com/amchdd/subdomainabber/pkg/signatures"
)

type verificationRuntime struct {
	engine *verify.Engine
}

func loadVerificationSignatureBase(cfg *config.Config) ([]signatures.Fingerprint, error) {
	result, err := signatures.LoadEmbedded()
	if err != nil {
		return nil, fmt.Errorf("carregando o catálogo embutido: %w", err)
	}
	if cfg != nil && cfg.SigsFile != "" {
		additional, err := signatures.LoadFromFile(cfg.SigsFile)
		if err != nil {
			return nil, err
		}
		result = append(result, additional...)
	}
	if cfg != nil && cfg.SigsDir != "" {
		additional, err := signatures.LoadFromDir(cfg.SigsDir)
		if err != nil {
			return nil, err
		}
		result = append(result, additional...)
	}
	return signatures.MergeSignatures(result), nil
}

func verificationProfileKey(profile *core.ScanProfile) string {
	if profile == nil {
		return "legacy"
	}
	data, err := json.Marshal(profile)
	if err != nil {
		return fmt.Sprintf("perfil-inválido:%p", profile)
	}
	return string(data)
}

func buildVerificationRuntimes(
	hosts []core.HostAnalysis,
	resolver *dns.Resolver,
	cfg *config.Config,
	limiter ratelimit.Waiter,
	sharedClient *http.Client,
	baseSignatures []signatures.Fingerprint,
	db *storage.Store,
) (map[string]verificationRuntime, error) {
	groups := make(map[string][]core.HostAnalysis)
	profiles := make(map[string]*core.ScanProfile)
	for _, host := range hosts {
		key := verificationProfileKey(host.ScanProfile)
		groups[key] = append(groups[key], host)
		profiles[key] = host.ScanProfile
	}

	runtimes := make(map[string]verificationRuntime, len(groups))
	for key, group := range groups {
		runtime, err := buildVerificationRuntime(profiles[key], group, resolver, cfg, limiter, sharedClient, baseSignatures, db)
		if err != nil {
			return nil, fmt.Errorf("preparando perfil de revalidação: %w", err)
		}
		runtimes[key] = runtime
	}
	return runtimes, nil
}

func buildVerificationRuntime(
	profile *core.ScanProfile,
	hosts []core.HostAnalysis,
	resolver *dns.Resolver,
	cfg *config.Config,
	limiter ratelimit.Waiter,
	sharedClient *http.Client,
	baseSignatures []signatures.Fingerprint,
	db *storage.Store,
) (verificationRuntime, error) {
	allSignatures := append([]signatures.Fingerprint(nil), baseSignatures...)
	if profile != nil && profile.CheckNS {
		allSignatures = signatures.MergeSignatures(allSignatures, signatures.BuiltinNSSignatures())
	}
	digest, err := signatures.Digest(allSignatures)
	if err != nil {
		return verificationRuntime{}, err
	}

	timeout := time.Duration(cfg.Timeout) * time.Second
	collectors := []evidence.Collector{
		evidence.NewCNAMECollector(resolver, allSignatures),
		evidence.NewMXCollector(resolver, allSignatures),
		evidence.NewTXTCollector(allSignatures),
		evidence.NewSRVCollector(resolver, allSignatures),
	}
	tlsCollector := evidence.NewTLSCollector(allSignatures, timeout)
	tlsCollector.SetRequestLimiter(limiter)
	httpCollector := evidence.NewHTTPCollector(
		allSignatures,
		timeout,
		cfg.Proxy,
		profile != nil && profile.FollowRedirects,
		profileUserAgent(profile),
		profile != nil && profile.FetchHeaders,
	)
	if err := httpCollector.Validate(); err != nil {
		return verificationRuntime{}, fmt.Errorf("configurando o coletor HTTP: %w", err)
	}
	httpCollector.SetRequestLimiter(limiter)
	collectors = append(collectors,
		tlsCollector,
		evidence.NewIPCollector(resolver, allSignatures),
		evidence.NewCAACollector(),
		httpCollector,
	)

	if profile != nil && profile.RelatedImpactInScope {
		roots := make([]string, 0, len(hosts))
		for _, host := range hosts {
			if root := dns.ExtractRootDomain(host.Host); root != "" {
				roots = append(roots, root)
			}
		}
		cookieCollector := evidence.NewCookieScopeCollector(timeout, sharedClient)
		corsCollector := evidence.NewCORSScopeCollector(timeout, sharedClient)
		cookieCollector.SetAllowedRootDomains(roots)
		corsCollector.SetAllowedRootDomains(roots)
		collectors = append(collectors, cookieCollector, corsCollector)
	}
	if profile != nil && profile.CheckNS {
		collectors = append(collectors, evidence.NewNSCollector(resolver, allSignatures))
	}
	if profile != nil && profile.CheckEmail {
		emailCollector := evidence.NewEmailSecurityCollector(resolver)
		emailCollector.SetSignatures(allSignatures)
		collectors = append(collectors, emailCollector)
	}
	if profile != nil && (profile.CheckHeaders || profile.CheckRedirects) {
		collectors = append(collectors, evidence.NewHttpSecurityCollectorForChecks(profile.CheckHeaders, profile.CheckRedirects, sharedClient))
	}
	if profile != nil && profile.CheckShadowIT {
		collectors = append(collectors, evidence.NewShadowITCollector())
	}
	if profile != nil && profile.CheckAXFR {
		collectors = append(collectors, evidence.NewZoneTransferCollector(resolver))
	}
	if profile != nil && profile.CheckDNSSEC {
		collectors = append(collectors, evidence.NewDNSSECCollector(resolver))
	}
	if profile != nil && profile.CheckEvasion {
		mutator := evidence.NewHTTPMutatorCollector(allSignatures, timeout)
		mutator.SetRequestLimiter(limiter)
		mutator.SetLimits(7, timeout*4)
		if err := mutator.ConfigureProxy(cfg.Proxy); err != nil {
			return verificationRuntime{}, fmt.Errorf("configurando proxy do HTTP Mutator: %w", err)
		}
		collectors = append(collectors, mutator)
	}

	registry := evidence.NewRegistry(collectors)
	registry.BeginBatch()
	verifierEngine := verifiers.NewEngine(verifiers.Config{
		Client:     sharedClient,
		CheckCloud: profile != nil && profile.CheckCloud,
	})
	engine := verify.NewEngine(resolver, registry, verifierEngine, db)
	engine.RequireCompatibleProfile(digest)
	return verificationRuntime{engine: engine}, nil
}

func profileUserAgent(profile *core.ScanProfile) string {
	if profile == nil {
		return ""
	}
	return profile.UserAgent
}
