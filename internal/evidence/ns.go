package evidence

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/dns"
	"github.com/amchdd/subdomainabber/internal/domainutil"
	"github.com/amchdd/subdomainabber/pkg/signatures"
)

// NSCollector avalia o corte de zona autoritativo real e a delegação publicada
// pela zona pai. Uma delegação quebrada permanece candidata até que uma verificação
// da possibilidade de reivindicação específica do provedor prove o contrário.
type NSCollector struct {
	resolver   *dns.Resolver
	signatures []signatures.Fingerprint
}

func NewNSCollector(res *dns.Resolver, sigs []signatures.Fingerprint) *NSCollector {
	return &NSCollector{resolver: res, signatures: sigs}
}

func (c *NSCollector) Phase() CollectorPhase { return PhaseProviderDiscovery }

func (c *NSCollector) Collect(ctx context.Context, analysis *core.HostAnalysis) error {
	analysis.AddTestedVector("NS_DELEGATION")

	zoneInfo, err := c.resolver.FindAuthoritativeZone(ctx, analysis.Host)
	if err != nil || len(zoneInfo.Nameservers) == 0 {
		return nil
	}
	candidate := &core.DelegationCandidate{
		Zone: zoneInfo.Zone, ParentZone: zoneInfo.ParentZone,
		DelegatedNameservers:     append([]string(nil), zoneInfo.Nameservers...),
		ParentHasDS:              zoneInfo.ParentHasDS,
		ParentDSChecked:          zoneInfo.ParentDSChecked,
		ParentDelegationVerified: zoneInfo.ParentDelegationVerified,
		Claimability:             core.ClaimabilityNotVerified,
	}
	if zoneInfo.ParentDelegationVerified {
		candidate.ParentDelegatedNameservers = append([]string(nil), zoneInfo.Nameservers...)
	}

	delegatedNameservers := uniqueNames(zoneInfo.Nameservers)
	failed := make(map[string]struct{})
	for _, nsHost := range delegatedNameservers {
		observation := core.DelegationNSObservation{
			Nameserver: nsHost, Status: core.DNSStatusError,
			Glue: append([]string(nil), zoneInfo.Glue[nsHost]...),
		}
		service, id := c.providerForNS(nsHost)
		observation.Service, observation.ProviderID = service, id

		addressStatus := c.resolver.ResolveAddressStatus(ctx, nsHost)
		observation.Resolvable = addressStatus == core.DNSStatusResolved
		addressMissing := !observation.Resolvable &&
			(addressStatus == core.DNSStatusNXDomain || addressStatus == core.DNSStatusNoData)
		if addressMissing {
			candidate.Unresolvable = append(candidate.Unresolvable, nsHost)
			failed[nsHost] = struct{}{}
		}

		health, _ := c.resolver.CheckNSHealth(ctx, nsHost, zoneInfo.Zone)
		observation.Status = nsHealthStatus(health)
		switch health {
		case "HEALTHY":
			candidate.Responsive = append(candidate.Responsive, nsHost)
			if addressMissing {
				delete(failed, nsHost)
				candidate.Unresolvable = removeName(candidate.Unresolvable, nsHost)
			}
		case "REFUSED", "NXDOMAIN", "LAME":
			candidate.Lame = append(candidate.Lame, nsHost)
			failed[nsHost] = struct{}{}
			typeName := "LAME_DELEGATION"
			if health == "NXDOMAIN" {
				typeName = "NS_NXDOMAIN"
			}
			analysis.AddEvidence(core.Evidence{
				Type: typeName, Source: nsHost,
				Description: fmt.Sprintf("A consulta SOA autoritativa de %s retornou %s", zoneInfo.Zone, health),
				Weight:      20, Confidence: 90,
				Metadata: map[string]string{"zone": zoneInfo.Zone, "ns_status": health},
			})
		case "SERVFAIL":
			candidate.Lame = append(candidate.Lame, nsHost)
			analysis.AddEvidence(core.Evidence{
				Type: "NS_SERVFAIL", Source: nsHost,
				Description: fmt.Sprintf("A consulta SOA autoritativa de %s retornou SERVFAIL", zoneInfo.Zone),
				Weight:      10, Confidence: 70, Metadata: map[string]string{"zone": zoneInfo.Zone},
			})
		case "TIMEOUT":
			analysis.AddEvidence(core.Evidence{
				Type: "NS_TIMEOUT", Source: nsHost,
				Description: "O servidor NS não respondeu antes do tempo limite",
				Weight:      1, Confidence: 30, Metadata: map[string]string{"zone": zoneInfo.Zone},
			})
		}
		if addressMissing && health != "HEALTHY" {
			analysis.AddEvidence(core.Evidence{
				Type: "NS_ORPHANED", Source: nsHost,
				Description: "O nome do servidor NS não possui endereço A ou AAAA",
				Weight:      20, Confidence: 90,
				Metadata: map[string]string{"zone": zoneInfo.Zone, "dns_status": string(addressStatus)},
			})
		}
		candidate.Nameservers = append(candidate.Nameservers, observation)
	}

	candidate.ProviderID, candidate.Provider = uniformDelegationProvider(candidate.Nameservers)

	allFailed := len(failed) == len(delegatedNameservers) && len(failed) > 0
	hasDelegationConcern := len(candidate.Lame) > 0 || len(candidate.Unresolvable) > 0
	if hasDelegationConcern && candidate.ProviderID != "" {
		analysis.AddEvidence(core.Evidence{
			Type: "NS_PROVIDER_MATCH", Source: candidate.Provider,
			Description: fmt.Sprintf("A delegação afetada usa o provedor conhecido %s", candidate.Provider),
			Weight:      1, Confidence: 90,
			Metadata: map[string]string{
				"zone": zoneInfo.Zone, "provider_id": candidate.ProviderID,
				"nameservers": strings.Join(candidate.DelegatedNameservers, ","),
			},
		})
	}
	if allFailed {
		analysis.AddEvidence(core.Evidence{
			Type: "NS_ALL_DEAD", Source: "DNS",
			Description: fmt.Sprintf("Todos os %d servidores NS delegados únicos falharam de forma conclusiva", len(failed)),
			Weight:      30, Confidence: 95,
			Metadata: map[string]string{"zone": zoneInfo.Zone, "failed_unique": fmt.Sprint(len(failed))},
		})
		analysis.AddEvidence(core.Evidence{
			Type: "DELEGATION_BROKEN", Source: "DNS",
			Description: fmt.Sprintf("A delegação de %s publicada pela zona pai aponta apenas para servidores NS que falharam", zoneInfo.Zone),
			Weight:      40, Confidence: 95,
			Metadata: map[string]string{
				"zone": zoneInfo.Zone, "parent_zone": zoneInfo.ParentZone,
				"parent_delegation_verified": fmt.Sprint(zoneInfo.ParentDelegationVerified),
				"parent_has_ds":              fmt.Sprint(zoneInfo.ParentHasDS),
				"parent_ds_checked":          fmt.Sprint(zoneInfo.ParentDSChecked),
				"claimability":               string(candidate.Claimability),
			},
		})
	}
	takeoverCandidate := allFailed && zoneInfo.ParentDelegationVerified && candidate.ProviderID != "" &&
		zoneInfo.ParentDSChecked && !zoneInfo.ParentHasDS
	if takeoverCandidate {
		analysis.AddEvidence(core.Evidence{
			Type: "DELEGATION_TAKEOVER_CANDIDATE", Source: candidate.Provider,
			Description: fmt.Sprintf("A delegação quebrada de %s, publicada pela zona pai, usa um provedor DNS conhecido; a recriação da zona não foi comprovada", zoneInfo.Zone),
			Weight:      50, Confidence: 80,
			Metadata: map[string]string{
				"zone": zoneInfo.Zone, "parent_zone": zoneInfo.ParentZone,
				"provider_id": candidate.ProviderID, "claimability": string(candidate.Claimability),
			},
		})
	}

	sort.Strings(candidate.Responsive)
	sort.Strings(candidate.Lame)
	sort.Strings(candidate.Unresolvable)
	analysis.Delegation = candidate
	// Uma zona autoritativa do provedor é infraestrutura comum. Ela só se torna
	// candidata a reivindicação ativa quando a delegação publicada pela zona pai,
	// a falha completa de NS e as precondições de DNSSEC estiverem comprovadas.
	if takeoverCandidate {
		analysis.AddProviderCandidate(core.ProviderCandidate{
			ProviderID: candidate.ProviderID, Service: candidate.Provider,
			Vector: "NS", Resource: candidate.Zone,
			Metadata: map[string]string{
				"zone": candidate.Zone, "parent_zone": candidate.ParentZone,
				"delegated_nameservers": strings.Join(candidate.DelegatedNameservers, ","),
			},
		})
	}
	return nil
}

func (c *NSCollector) providerForNS(host string) (string, string) {
	for _, sig := range c.signatures {
		for _, pattern := range sig.NSFingerprints {
			if domainutil.MatchDNSProviderPattern(host, pattern) {
				return sig.Service, providerID(sig.Service)
			}
		}
	}
	return "", ""
}

func nsHealthStatus(status string) core.DNSStatus {
	switch status {
	case "HEALTHY":
		return core.DNSStatusResolved
	case "REFUSED":
		return core.DNSStatusRefused
	case "SERVFAIL":
		return core.DNSStatusServFail
	case "NXDOMAIN":
		return core.DNSStatusNXDomain
	case "LAME":
		return core.DNSStatusNoData
	case "TIMEOUT":
		return core.DNSStatusTimeout
	default:
		return core.DNSStatusError
	}
}

func uniqueNames(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func uniformDelegationProvider(observations []core.DelegationNSObservation) (string, string) {
	if len(observations) == 0 {
		return "", ""
	}
	providerID, service := observations[0].ProviderID, observations[0].Service
	if providerID == "" {
		return "", ""
	}
	for _, observation := range observations[1:] {
		if observation.ProviderID == "" || observation.ProviderID != providerID {
			return "", ""
		}
	}
	return providerID, service
}

func removeName(values []string, target string) []string {
	result := values[:0]
	for _, value := range values {
		if value != target {
			result = append(result, value)
		}
	}
	return result
}
