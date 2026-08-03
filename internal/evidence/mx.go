package evidence

import (
	"context"
	"fmt"
	"strings"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/dns"
	"github.com/amchdd/subdomainabber/internal/domainutil"
	"github.com/amchdd/subdomainabber/pkg/signatures"
)

type MXCollector struct {
	resolver *dns.Resolver
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

func NewMXCollector(resolver *dns.Resolver, sigs []signatures.Fingerprint) *MXCollector {
	return &MXCollector{resolver: resolver, sigs: sigs}
}

func (c *MXCollector) Collect(ctx context.Context, analysis *core.HostAnalysis) error {
	analysis.AddTestedVector("MX")
	for _, rawTarget := range analysis.DNS.MX {
		if strings.TrimSpace(rawTarget) == "." {
			analysis.AddEvidence(core.Evidence{
				Type: "NULL_MX_PRESENT", Source: "DNS",
				Description: "O domínio publica Null MX (MX 0 .), indicando intencionalmente que não recebe e-mail por SMTP.",
				Weight:      0, Confidence: 100, IsNegative: true,
			})
			continue
		}
		target := strings.TrimSuffix(strings.ToLower(rawTarget), ".")
		if target == "" {
			continue
		}
		candidate := core.MXCandidate{
			Target: target, RegistrableDomain: dns.ExtractRootDomain(target),
			Ownership: externalTargetOwnership(target), RegistrationStatus: "NOT_CHECKED",
			Claimability: core.ClaimabilityNotVerified,
		}
		for _, rule := range builtinMXTargetProviders {
			if dnsSuffixMatch(target, rule.suffix) {
				candidate.Provider, candidate.ProviderID = rule.provider, providerID(rule.provider)
				candidate.Ownership = "PROVIDER_OWNED"
				addMXProviderEvidence(analysis, candidate, 95)
				break
			}
		}
		if candidate.ProviderID == "" {
			for _, sig := range c.sigs {
				for _, fingerprint := range sig.MXFingerprints {
					if domainutil.MatchDNSProviderPattern(target, fingerprint) {
						candidate.Provider, candidate.ProviderID = sig.Service, providerID(sig.Service)
						candidate.Ownership = "PROVIDER_OWNED"
						confidence := sig.MXConfidence
						if confidence == 0 {
							confidence = sig.Confidence
						}
						addMXProviderEvidence(analysis, candidate, confidence)
						break
					}
				}
				if candidate.ProviderID != "" {
					break
				}
			}
		}

		candidate.DNSStatus = c.resolver.ResolveAddressStatus(ctx, target)
		if candidate.ProviderID != "" {
			analysis.AddProviderCandidate(core.ProviderCandidate{
				ProviderID: candidate.ProviderID, Service: candidate.Provider,
				Vector: "MX", Resource: target,
				Metadata: map[string]string{"registrable_domain": candidate.RegistrableDomain, "ownership": candidate.Ownership},
			})
		}
		switch candidate.DNSStatus {
		case core.DNSStatusNXDomain, core.DNSStatusNoData:
			analysis.AddEvidence(core.Evidence{
				Type: "MX_BROKEN", Source: "DNS",
				Description: fmt.Sprintf("O destino MX %s apresentou o estado DNS %s; a registrabilidade e o controle de entrega não foram verificados", target, candidate.DNSStatus),
				Weight:      20, Confidence: 90,
				Metadata: map[string]string{
					"mx_target": target, "dns_status": string(candidate.DNSStatus),
					"registrable_domain": candidate.RegistrableDomain, "ownership": candidate.Ownership,
					"registration_status": candidate.RegistrationStatus, "claimability": string(candidate.Claimability),
				},
			})
		case core.DNSStatusTimeout, core.DNSStatusServFail, core.DNSStatusError:
			analysis.AddEvidence(core.Evidence{
				Type: "MX_UNRESOLVABLE", Source: "DNS",
				Description: fmt.Sprintf("O destino MX %s não pôde ser avaliado de forma confiável (%s)", target, candidate.DNSStatus),
				Weight:      1, Confidence: 40,
				Metadata: map[string]string{"mx_target": target, "dns_status": string(candidate.DNSStatus)},
			})
		}
		analysis.MXCandidates = append(analysis.MXCandidates, candidate)
	}
	return nil
}

func addMXProviderEvidence(analysis *core.HostAnalysis, candidate core.MXCandidate, confidence int) {
	analysis.AddEvidence(core.Evidence{
		Type: "MX_PROVIDER_MATCH", Source: candidate.Provider,
		Description: fmt.Sprintf("O destino MX %s pertence ao provedor %s", candidate.Target, candidate.Provider),
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
