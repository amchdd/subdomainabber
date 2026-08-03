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

type SRVCollector struct {
	resolver *dns.Resolver
	sigs     []signatures.Fingerprint
}

var builtinSRVTargetProviders = []struct{ suffix, provider string }{
	{"online.lync.com", "Microsoft 365"},
	{"outlook.com", "Microsoft 365"},
	{"manage.microsoft.com", "Microsoft Intune"},
	{"windows.net", "Microsoft Entra ID"},
	{"ciscospark.com", "Cisco Webex"},
}

func NewSRVCollector(resolver *dns.Resolver, sigs []signatures.Fingerprint) *SRVCollector {
	return &SRVCollector{resolver: resolver, sigs: sigs}
}

func (c *SRVCollector) Collect(ctx context.Context, analysis *core.HostAnalysis) error {
	analysis.AddTestedVector("SRV")
	records := analysis.DNS.SRVRecords
	if len(records) == 0 {
		for _, legacy := range analysis.DNS.SRV {
			if record, ok := parseLegacySRV(analysis.Host, legacy); ok {
				records = append(records, record)
			}
		}
	}
	for _, record := range records {
		if record.Target == "" || record.Target == "." {
			continue
		}
		candidate := core.SRVCandidate{
			Record: record, RegistrableDomain: dns.ExtractRootDomain(record.Target),
			Ownership: externalTargetOwnership(record.Target), RegistrationStatus: "NOT_CHECKED",
			Claimability: core.ClaimabilityNotVerified,
		}
		for _, rule := range builtinSRVTargetProviders {
			if dnsSuffixMatch(record.Target, rule.suffix) {
				candidate.Provider, candidate.ProviderID = rule.provider, providerID(rule.provider)
				candidate.Ownership = "PROVIDER_OWNED"
				addSRVProviderEvidence(analysis, candidate, 95)
				break
			}
		}
		if candidate.ProviderID == "" {
			for _, sig := range c.sigs {
				for _, fingerprint := range sig.SRVFingerprints {
					if domainutil.MatchDNSProviderPattern(record.Target, fingerprint) {
						candidate.Provider, candidate.ProviderID = sig.Service, providerID(sig.Service)
						candidate.Ownership = "PROVIDER_OWNED"
						confidence := sig.SRVConfidence
						if confidence == 0 {
							confidence = sig.Confidence
						}
						addSRVProviderEvidence(analysis, candidate, confidence)
						break
					}
				}
				if candidate.ProviderID != "" {
					break
				}
			}
		}
		candidate.DNSStatus = c.resolver.ResolveAddressStatus(ctx, record.Target)
		if candidate.ProviderID != "" {
			analysis.AddProviderCandidate(core.ProviderCandidate{
				ProviderID: candidate.ProviderID, Service: candidate.Provider,
				Vector: "SRV", Resource: record.Target,
				Metadata: map[string]string{"owner": record.Owner, "port": strconv.Itoa(int(record.Port))},
			})
		}
		switch candidate.DNSStatus {
		case core.DNSStatusNXDomain, core.DNSStatusNoData:
			analysis.AddEvidence(core.Evidence{
				Type: "SRV_BROKEN", Source: "DNS",
				Description: fmt.Sprintf("O registro SRV %s aponta para %s (%s); a reivindicabilidade do destino não foi verificada", record.Owner, record.Target, candidate.DNSStatus),
				Weight:      20, Confidence: 90,
				Metadata: map[string]string{
					"srv_owner": record.Owner, "srv_target": record.Target,
					"priority": strconv.Itoa(int(record.Priority)), "weight": strconv.Itoa(int(record.Weight)), "port": strconv.Itoa(int(record.Port)),
					"dns_status": string(candidate.DNSStatus), "registration_status": candidate.RegistrationStatus,
					"ownership": candidate.Ownership, "claimability": string(candidate.Claimability),
				},
			})
		case core.DNSStatusTimeout, core.DNSStatusServFail, core.DNSStatusError:
			analysis.AddEvidence(core.Evidence{
				Type: "SRV_UNRESOLVABLE", Source: "DNS",
				Description: fmt.Sprintf("O destino SRV %s não pôde ser avaliado de forma confiável (%s)", record.Target, candidate.DNSStatus),
				Weight:      1, Confidence: 40,
				Metadata: map[string]string{"srv_owner": record.Owner, "srv_target": record.Target, "dns_status": string(candidate.DNSStatus)},
			})
		}
		analysis.SRVCandidates = append(analysis.SRVCandidates, candidate)
	}
	return nil
}

func addSRVProviderEvidence(analysis *core.HostAnalysis, candidate core.SRVCandidate, confidence int) {
	analysis.AddEvidence(core.Evidence{
		Type: "SRV_PROVIDER_MATCH", Source: candidate.Provider,
		Description: fmt.Sprintf("O registro SRV %s aponta para o provedor %s", candidate.Record.Owner, candidate.Provider),
		Weight:      1, Confidence: confidence,
		Metadata: map[string]string{"srv_owner": candidate.Record.Owner, "srv_target": candidate.Record.Target, "provider_id": candidate.ProviderID, "ownership": candidate.Ownership},
	})
}

func parseLegacySRV(owner, value string) (core.SRVRecord, bool) {
	separator := strings.LastIndex(value, ":")
	if separator < 1 {
		return core.SRVRecord{}, false
	}
	port, err := strconv.ParseUint(value[separator+1:], 10, 16)
	if err != nil {
		return core.SRVRecord{}, false
	}
	return core.SRVRecord{Owner: owner, Target: strings.TrimSuffix(strings.ToLower(value[:separator]), "."), Port: uint16(port)}, true
}
