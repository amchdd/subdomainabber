package evidence

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/dns"
	"github.com/amchdd/subdomainabber/internal/domainutil"
	"github.com/amchdd/subdomainabber/pkg/signatures"
)

type targetResolver interface {
	ResolveAddressStatus(context.Context, string) core.DNSStatus
	ResolveCNAMEChain(context.Context, string) ([]string, error)
}

type MXCollector struct {
	resolver targetResolver
	sigs     []signatures.Fingerprint
}

var builtinMXTargetProviders = []struct{ suffix, provider string }{
	{"mail.protection.outlook.com", "Microsoft 365"},
	{"aspmx.l.google.com", "Google Workspace"},
	{"googlemail.com", "Google Workspace"},
	{"amazonses.com", "Amazon SES"},
	{"sendgrid.net", "Twilio SendGrid"},
	{"mailgun.org", "Mailgun"},
	{"zendesk.com", "Zendesk"},
}

func NewMXCollector(resolver targetResolver, sigs []signatures.Fingerprint) *MXCollector {
	return &MXCollector{resolver: resolver, sigs: sigs}
}

func (collector *MXCollector) Collect(ctx context.Context, analysis *core.HostAnalysis) error {
	analysis.AddTestedVector("MX")
	records := analysis.DNS.MXRecords
	if len(records) == 0 {
		for _, target := range analysis.DNS.MX {
			records = append(records, core.MXRecord{Target: target})
		}
	}
	var candidates []core.MXCandidate
	for _, record := range records {
		if strings.TrimSpace(record.Target) == "." {
			analysis.AddEvidence(core.Evidence{
				Type: "NULL_MX_PRESENT", Source: "DNS",
				Description: "O domínio publica Null MX e declara que não recebe e-mail por SMTP.",
				Weight:      0, Confidence: 100, IsNegative: true,
			})
			continue
		}
		target := strings.TrimSuffix(strings.ToLower(record.Target), ".")
		if target == "" {
			continue
		}
		candidate := core.MXCandidate{
			Target: target, Preference: record.Preference, FinalTarget: target,
			RegistrableDomain: dns.ExtractRootDomain(target), Ownership: externalTargetOwnership(target),
			RegistrationStatus: "NOT_CHECKED", Claimability: core.ClaimabilityNotVerified,
		}
		candidate.CNAME, _ = collector.resolver.ResolveCNAMEChain(ctx, target)
		if len(candidate.CNAME) > 0 {
			candidate.FinalTarget = candidate.CNAME[len(candidate.CNAME)-1]
		}
		collector.matchProvider(analysis, &candidate)
		candidate.DNSStatus = collector.resolver.ResolveAddressStatus(ctx, candidate.FinalTarget)
		if candidate.ProviderID != "" {
			analysis.AddProviderCandidate(core.ProviderCandidate{
				ProviderID: candidate.ProviderID, Service: candidate.Provider,
				Vector: "MX", Resource: target,
				Metadata: map[string]string{"registrable_domain": candidate.RegistrableDomain, "ownership": candidate.Ownership},
			})
		}
		candidates = append(candidates, candidate)
	}
	collector.addStatusEvidence(analysis, candidates)
	analysis.MXCandidates = append(analysis.MXCandidates, candidates...)
	return nil
}

func (collector *MXCollector) matchProvider(analysis *core.HostAnalysis, candidate *core.MXCandidate) {
	names := append([]string{candidate.Target}, candidate.CNAME...)
	for _, rule := range builtinMXTargetProviders {
		for _, name := range names {
			if dnsSuffixMatch(name, rule.suffix) {
				candidate.Provider, candidate.ProviderID = rule.provider, providerID(rule.provider)
				candidate.Ownership = "PROVIDER_OWNED"
				addMXProviderEvidence(analysis, *candidate, 95)
				return
			}
		}
	}
	for _, sig := range collector.sigs {
		for _, fingerprint := range sig.MXFingerprints {
			for _, name := range names {
				if !domainutil.MatchDNSProviderPattern(name, fingerprint) {
					continue
				}
				candidate.Provider, candidate.ProviderID = sig.Service, providerID(sig.Service)
				candidate.Ownership = "PROVIDER_OWNED"
				confidence := sig.MXConfidence
				if confidence == 0 {
					confidence = sig.Confidence
				}
				addMXProviderEvidence(analysis, *candidate, confidence)
				return
			}
		}
	}
}

func (collector *MXCollector) addStatusEvidence(analysis *core.HostAnalysis, candidates []core.MXCandidate) {
	if len(candidates) == 0 {
		return
	}
	minPreference := candidates[0].Preference
	for _, candidate := range candidates[1:] {
		if candidate.Preference < minPreference {
			minPreference = candidate.Preference
		}
	}
	healthy := 0
	for _, candidate := range candidates {
		if candidate.DNSStatus == core.DNSStatusResolved {
			healthy++
		}
	}
	for index := range candidates {
		candidate := &candidates[index]
		candidate.Role = "fallback"
		if candidate.Preference == minPreference {
			candidate.Role = "primary"
		}
		candidate.HealthyAlternatives = healthy
		if candidate.DNSStatus == core.DNSStatusResolved {
			candidate.HealthyAlternatives--
			continue
		}
		metadata := mxMetadata(*candidate)
		switch candidate.DNSStatus {
		case core.DNSStatusNXDomain, core.DNSStatusNoData:
			typeName, weight := "MX_BROKEN", 20
			description := fmt.Sprintf("O destino MX %s está quebrado e não há alternativa saudável.", candidate.Target)
			if healthy > 0 && candidate.Role == "primary" {
				typeName, weight = "MX_PRIMARY_BROKEN_WITH_FALLBACK", 10
				description = fmt.Sprintf("O MX primário %s está quebrado, mas existe fallback saudável.", candidate.Target)
			} else if healthy > 0 {
				typeName, weight = "MX_BACKUP_BROKEN", 5
				description = fmt.Sprintf("O MX de fallback %s está quebrado; o primário permanece saudável.", candidate.Target)
			}
			analysis.AddEvidence(core.Evidence{Type: typeName, Source: "DNS", Description: description, Weight: weight, Confidence: 90, Metadata: metadata})
		case core.DNSStatusTimeout, core.DNSStatusServFail, core.DNSStatusError:
			analysis.AddEvidence(core.Evidence{
				Type: "MX_UNRESOLVABLE", Source: "DNS",
				Description: fmt.Sprintf("O destino MX %s não pôde ser avaliado de forma confiável (%s).", candidate.Target, candidate.DNSStatus),
				Weight:      1, Confidence: 40, Metadata: metadata,
			})
		}
	}
}

func mxMetadata(candidate core.MXCandidate) map[string]string {
	return map[string]string{
		"mx_target": candidate.Target, "final_target": candidate.FinalTarget,
		"preference": strconv.Itoa(int(candidate.Preference)), "role": candidate.Role,
		"healthy_alternatives": strconv.Itoa(candidate.HealthyAlternatives),
		"dns_status":           string(candidate.DNSStatus), "cname_chain": strings.Join(candidate.CNAME, ","),
		"registrable_domain": candidate.RegistrableDomain, "ownership": candidate.Ownership,
		"registration_status": candidate.RegistrationStatus, "claimability": string(candidate.Claimability),
	}
}

func addMXProviderEvidence(analysis *core.HostAnalysis, candidate core.MXCandidate, confidence int) {
	analysis.AddEvidence(core.Evidence{
		Type: "MX_PROVIDER_MATCH", Source: candidate.Provider,
		Description: fmt.Sprintf("O destino MX %s pertence ao provedor %s.", candidate.Target, candidate.Provider),
		Weight:      1, Confidence: confidence,
		Metadata: map[string]string{"mx_target": candidate.Target, "provider_id": candidate.ProviderID, "ownership": candidate.Ownership},
	})
}

func externalTargetOwnership(target string) string {
	root := dns.ExtractRootDomain(target)
	for _, providerRoot := range []string{"google.com", "googlemail.com", "outlook.com", "microsoft.com", "amazonaws.com", "amazonses.com", "sendgrid.net", "mailgun.org", "zendesk.com", "windows.net", "ciscospark.com"} {
		if root == providerRoot {
			return "PROVIDER_OWNED"
		}
	}
	return "EXTERNAL_UNVERIFIED"
}

func dnsSuffixMatch(host, suffix string) bool {
	host, suffix = strings.ToLower(strings.TrimSuffix(host, ".")), strings.ToLower(strings.TrimSuffix(suffix, "."))
	return host == suffix || strings.HasSuffix(host, "."+suffix)
}
