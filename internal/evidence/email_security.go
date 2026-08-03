package evidence

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/dns"
	"github.com/amchdd/subdomainabber/internal/domainutil"
	"github.com/amchdd/subdomainabber/pkg/signatures"
	"golang.org/x/sync/singleflight"
)

type EmailSecurityCollector struct {
	resolver emailSecurityResolver
	sigs     []signatures.Fingerprint
	cache    sync.Map
	group    singleflight.Group
}

type emailSecurityResolver interface {
	ResolveMX(context.Context, string) ([]string, error)
	ResolveTXTWithStatus(context.Context, string) ([]string, core.DNSStatus, error)
}

type emailSecurityResult struct {
	evidences          []core.Evidence
	providerCandidates []core.ProviderCandidate
	spfCandidates      []core.SPFCandidate
}

// A forma variádica preserva a compatibilidade dos chamadores e permite que o
// fluxo de varredura compartilhe seu resolver DNS configurado.
func NewEmailSecurityCollector(resolvers ...*dns.Resolver) *EmailSecurityCollector {
	if len(resolvers) > 0 && resolvers[0] != nil {
		return &EmailSecurityCollector{resolver: resolvers[0]}
	}
	return &EmailSecurityCollector{resolver: dns.New(nil)}
}

func (c *EmailSecurityCollector) SetSignatures(sigs []signatures.Fingerprint) {
	c.sigs = sigs
}

func (c *EmailSecurityCollector) Name() string { return "EmailSecurity" }

func (c *EmailSecurityCollector) BeginBatch() {
	c.cache = sync.Map{}
	c.group = singleflight.Group{}
}

func (c *EmailSecurityCollector) Collect(ctx context.Context, analysis *core.HostAnalysis) error {
	domain := dns.ExtractRootDomain(analysis.Host)
	if domain == "" {
		return nil
	}
	analysis.AddTestedVector("EMAIL")

	result, err := c.resultForDomain(ctx, domain)
	if err != nil {
		return nil
	}
	c.applyResult(analysis, result)
	return nil
}

func (c *EmailSecurityCollector) resultForDomain(ctx context.Context, domain string) (emailSecurityResult, error) {
	if cached, ok := c.cache.Load(domain); ok {
		return cloneEmailSecurityResult(cached.(emailSecurityResult)), nil
	}

	// Uma chamada cancelada não deve envenenar o resultado compartilhado. Se o
	// contexto que liderou o singleflight for cancelado, um chamador ainda ativo
	// refaz a coleta e pode preencher o cache do lote.
	for attempt := 0; attempt < 2; attempt++ {
		value, err, _ := c.group.Do(domain, func() (interface{}, error) {
			if cached, ok := c.cache.Load(domain); ok {
				return cloneEmailSecurityResult(cached.(emailSecurityResult)), nil
			}
			result := c.collectDomain(ctx, domain)
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			c.cache.Store(domain, cloneEmailSecurityResult(result))
			return result, nil
		})
		if err == nil {
			return cloneEmailSecurityResult(value.(emailSecurityResult)), nil
		}
		if ctx.Err() != nil {
			return emailSecurityResult{}, ctx.Err()
		}
	}
	return emailSecurityResult{}, context.Canceled
}

func (c *EmailSecurityCollector) collectDomain(ctx context.Context, domain string) emailSecurityResult {
	zoneAnalysis := &core.HostAnalysis{Host: domain}
	zoneAnalysis.InitMutex()
	mx, _ := c.resolver.ResolveMX(ctx, domain)
	txts, _, _ := c.resolver.ResolveTXTWithStatus(ctx, domain)
	c.validateSPF(ctx, zoneAnalysis, domain, txts, len(mx) > 0)

	dmarcOwner := "_dmarc." + domain
	dmarcTXT, status, _ := c.resolver.ResolveTXTWithStatus(ctx, dmarcOwner)
	hasDMARC := false
	for _, txt := range dmarcTXT {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=dmarc1") {
			hasDMARC = true
			break
		}
	}
	if !hasDMARC && len(mx) > 0 {
		zoneAnalysis.AddEvidence(core.Evidence{
			Type: "EMAIL_DMARC_MISSING", Source: "EmailSecurity",
			Description: fmt.Sprintf("Nenhuma política DMARC encontrada em %s (%s)", dmarcOwner, status),
			Weight:      0, Confidence: 95,
			Metadata: map[string]string{"owner": dmarcOwner, "dns_status": string(status), "category": "context"},
		})
	}
	return emailSecurityResult{
		evidences:          zoneAnalysis.Evidences,
		providerCandidates: zoneAnalysis.ProviderCandidates,
		spfCandidates:      zoneAnalysis.SPFCandidates,
	}
}

func (c *EmailSecurityCollector) applyResult(analysis *core.HostAnalysis, result emailSecurityResult) {
	for _, evidence := range result.evidences {
		analysis.AddEvidence(cloneEvidence(evidence))
	}
	for _, candidate := range result.providerCandidates {
		candidate.Metadata = cloneStringMap(candidate.Metadata)
		analysis.AddProviderCandidate(candidate)
	}
	for _, candidate := range result.spfCandidates {
		candidate.Chain = append([]string(nil), candidate.Chain...)
		analysis.SPFCandidates = append(analysis.SPFCandidates, candidate)
	}
}

func cloneEmailSecurityResult(result emailSecurityResult) emailSecurityResult {
	cloned := emailSecurityResult{
		evidences:          make([]core.Evidence, len(result.evidences)),
		providerCandidates: make([]core.ProviderCandidate, len(result.providerCandidates)),
		spfCandidates:      make([]core.SPFCandidate, len(result.spfCandidates)),
	}
	for index, evidence := range result.evidences {
		cloned.evidences[index] = cloneEvidence(evidence)
	}
	for index, candidate := range result.providerCandidates {
		candidate.Metadata = cloneStringMap(candidate.Metadata)
		cloned.providerCandidates[index] = candidate
	}
	for index, candidate := range result.spfCandidates {
		candidate.Chain = append([]string(nil), candidate.Chain...)
		cloned.spfCandidates[index] = candidate
	}
	return cloned
}

func cloneEvidence(evidence core.Evidence) core.Evidence {
	evidence.Metadata = cloneStringMap(evidence.Metadata)
	return evidence
}

func (c *EmailSecurityCollector) validateSPF(ctx context.Context, analysis *core.HostAnalysis, domain string, txts []string, mailRelevant bool) {
	spf := firstSPF(txts)
	if spf == "" {
		if mailRelevant {
			analysis.AddEvidence(core.Evidence{
				Type: "EMAIL_SPF_MISSING", Source: "EmailSecurity",
				Description: "O domínio possui registros MX, mas não publica uma política SPF",
				Weight:      0, Confidence: 100,
				Metadata: map[string]string{"domain": domain, "category": "context"},
			})
		}
		return
	}
	lower := strings.ToLower(spf)
	if strings.Contains(lower, "~all") || strings.Contains(lower, "?all") || strings.Contains(lower, "+all") {
		analysis.AddEvidence(core.Evidence{
			Type: "EMAIL_SPF_PERMISSIVE", Source: "EmailSecurity",
			Description: "A política SPF usa o mecanismo all de forma permissiva",
			Weight:      10, Confidence: 90,
			Metadata: map[string]string{"domain": domain, "category": "misconfiguration"},
		})
	}

	lookups := 0
	limitReported := false
	var walk func(currentDomain, record string, chain []string, path map[string]bool)
	walk = func(currentDomain, record string, chain []string, path map[string]bool) {
		currentDomain = strings.TrimSuffix(strings.ToLower(currentDomain), ".")
		if path[currentDomain] {
			analysis.AddEvidence(core.Evidence{
				Type: "SPF_INCLUDE_CYCLE", Source: "EmailSecurity",
				Description: "Ciclo de recursão SPF: " + strings.Join(append(chain, currentDomain), " -> "),
				Weight:      10, Confidence: 100,
				Metadata: map[string]string{"chain": strings.Join(append(chain, currentDomain), " -> "), "category": "misconfiguration"},
			})
			return
		}
		path[currentDomain] = true
		defer delete(path, currentDomain)

		for _, token := range strings.Fields(record) {
			mechanism, target, consumesLookup := spfMechanism(token)
			if !consumesLookup {
				continue
			}
			lookups++
			if lookups > 10 {
				if !limitReported {
					limitReported = true
					analysis.AddEvidence(core.Evidence{
						Type: "SPF_LOOKUP_LIMIT_EXCEEDED", Source: "EmailSecurity",
						Description: "A avaliação SPF excede o limite de dez termos que geram consultas DNS, definido pela RFC 7208",
						Weight:      20, Confidence: 100,
						Metadata: map[string]string{"domain": domain, "lookups": fmt.Sprint(lookups), "category": "misconfiguration"},
					})
				}
				return
			}
			if mechanism != "include" && mechanism != "redirect" {
				continue
			}
			target = strings.TrimSuffix(strings.ToLower(target), ".")
			if target == "" {
				continue
			}
			nextChain := append(append([]string(nil), chain...), target)
			targetTXT, status, _ := c.resolver.ResolveTXTWithStatus(ctx, target)
			if status == core.DNSStatusNXDomain {
				registrable := dns.ExtractRootDomain(target)
				ownership := spfOwnership(registrable)
				candidate := core.SPFCandidate{
					Domain: target, Mechanism: mechanism, Chain: nextChain,
					DNSStatus: status, RegistrableDomain: registrable,
					Ownership: ownership, RegistrationStatus: "NOT_CHECKED", Claimability: core.ClaimabilityNotVerified,
				}
				for _, sig := range c.sigs {
					for _, fingerprint := range sig.SPFFingerprints {
						if domainutil.MatchDNSProviderPattern(target, fingerprint) {
							candidate.Ownership = "PROVIDER_OWNED"
							analysis.AddProviderCandidate(core.ProviderCandidate{
								ProviderID: providerID(sig.Service), Service: sig.Service,
								Vector: "SPF", Resource: target,
								Metadata: map[string]string{"mechanism": mechanism, "chain": strings.Join(nextChain, " -> ")},
							})
							break
						}
					}
				}
				analysis.SPFCandidates = append(analysis.SPFCandidates, candidate)
				analysis.AddEvidence(core.Evidence{
					Type: "SPF_BROKEN_INCLUDE", Source: "EmailSecurity",
					Description: fmt.Sprintf("O destino %s do SPF %s é NXDOMAIN; registro e controle de e-mail não foram verificados", target, mechanism),
					Weight:      20, Confidence: 95,
					Metadata: map[string]string{
						"domain": target, "mechanism": mechanism, "chain": strings.Join(nextChain, " -> "),
						"dns_status": string(status), "registrable_domain": registrable,
						"ownership": ownership, "registration_status": "NOT_CHECKED",
						"claimability": string(core.ClaimabilityNotVerified),
					},
				})
				continue
			}
			nested := firstSPF(targetTXT)
			if status == core.DNSStatusNoData || (status == core.DNSStatusResolved && nested == "") {
				analysis.AddEvidence(core.Evidence{
					Type: "SPF_INCLUDE_WITHOUT_POLICY", Source: "EmailSecurity",
					Description: fmt.Sprintf("O destino %s do SPF %s existe, mas não publica uma política SPF", target, mechanism),
					Weight:      10, Confidence: 95,
					Metadata: map[string]string{"domain": target, "chain": strings.Join(nextChain, " -> "), "category": "misconfiguration"},
				})
				continue
			}
			if nested != "" {
				walk(target, nested, nextChain, path)
			}
		}
	}
	walk(domain, spf, []string{domain}, make(map[string]bool))
}

func firstSPF(txts []string) string {
	for _, txt := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=spf1") {
			return txt
		}
	}
	return ""
}

func spfMechanism(raw string) (mechanism, target string, consumesLookup bool) {
	token := strings.ToLower(strings.TrimSpace(raw))
	if token == "" {
		return "", "", false
	}
	if strings.ContainsRune("+-~?", rune(token[0])) {
		token = token[1:]
	}
	if strings.HasPrefix(token, "include:") {
		return "include", strings.TrimPrefix(token, "include:"), true
	}
	if strings.HasPrefix(token, "redirect=") {
		return "redirect", strings.TrimPrefix(token, "redirect="), true
	}
	if token == "a" || strings.HasPrefix(token, "a:") || strings.HasPrefix(token, "a/") {
		return "a", "", true
	}
	if token == "mx" || strings.HasPrefix(token, "mx:") || strings.HasPrefix(token, "mx/") {
		return "mx", "", true
	}
	if token == "ptr" || strings.HasPrefix(token, "ptr:") {
		return "ptr", "", true
	}
	if strings.HasPrefix(token, "exists:") {
		return "exists", strings.TrimPrefix(token, "exists:"), true
	}
	return "", "", false
}

func spfOwnership(registrable string) string {
	providerOwned := map[string]bool{
		"google.com": true, "outlook.com": true, "mailgun.org": true,
		"sendgrid.net": true, "amazonses.com": true, "mandrillapp.com": true,
	}
	if providerOwned[registrable] {
		return "PROVIDER_OWNED"
	}
	return "EXTERNAL_UNVERIFIED"
}
