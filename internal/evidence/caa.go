package evidence

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/dns"
)

type caaResolver interface {
	ResolveCAA(context.Context, string) ([]string, error)
}

type CAACollector struct {
	resolver caaResolver
}

func NewCAACollector(resolvers ...caaResolver) *CAACollector {
	collector := &CAACollector{}
	if len(resolvers) > 0 {
		collector.resolver = resolvers[0]
	}
	return collector
}

func (*CAACollector) Phase() CollectorPhase { return PhaseImpact }

func (collector *CAACollector) Collect(ctx context.Context, analysis *core.HostAnalysis) error {
	analysis.AddTestedVector("CAA")
	hostPolicy := caaPolicy(analysis.DNS.CAA)
	root := dns.ExtractRootDomain(analysis.Host)
	parentRecords, parentZone := parentCAA(ctx, collector.resolver, analysis.Host, root)
	parentPolicy := caaPolicy(parentRecords)
	effectiveRecords := analysis.DNS.CAA
	effectivePolicy := hostPolicy
	effectiveZone := analysis.Host
	if len(effectiveRecords) == 0 {
		effectiveRecords = parentRecords
		effectivePolicy = parentPolicy
		effectiveZone = parentZone
	}
	if len(effectivePolicy) > 0 {
		analysis.AddEvidence(core.Evidence{
			Type: "CAA_RECORD_PRESENT", Source: "DNS",
			Description: "A política CAA restringe as autoridades certificadoras permitidas.",
			Weight:      10, Confidence: 100, IsNegative: true,
			Metadata: map[string]string{"policy": strings.Join(effectivePolicy, ","), "zone": effectiveZone},
		})
	}
	if len(hostPolicy) > 0 && len(parentPolicy) > 0 && !sameStrings(hostPolicy, parentPolicy) {
		analysis.AddEvidence(core.Evidence{
			Type: "CAA_POLICY_INCONSISTENT", Source: "DNS",
			Description: "As políticas CAA do hostname e do ancestral mais próximo são diferentes.",
			Weight:      0, Confidence: 100,
			Metadata: map[string]string{"host_issuers": strings.Join(hostPolicy, ","), "zone_issuers": strings.Join(parentPolicy, ","), "zone": parentZone},
		})
	}
	issuer := tlsIssuer(analysis.Evidences)
	issuerDomain := issuerCAAName(issuer)
	allowed, restricted := caaIssuers(effectiveRecords, tlsHasWildcard(analysis.Evidences))
	if issuerDomain != "" && restricted && !containsCAA(allowed, issuerDomain) {
		analysis.AddEvidence(core.Evidence{
			Type: "CAA_ISSUER_MISMATCH", Source: "DNS/TLS",
			Description: fmt.Sprintf("O certificado observado foi emitido por %s, fora da política CAA coletada.", issuer),
			Weight:      0, Confidence: 90,
			Metadata: map[string]string{"tls_issuer": issuer, "issuer_domain": issuerDomain, "allowed_issuers": strings.Join(allowed, ",")},
		})
	}
	return nil
}

func parentCAA(ctx context.Context, resolver caaResolver, host, root string) ([]string, string) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	root = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(root), "."))
	if resolver == nil || host == "" || root == "" || host == root {
		return nil, ""
	}
	hostLabels := strings.Split(host, ".")
	rootLabels := strings.Split(root, ".")
	if len(hostLabels) <= len(rootLabels) || strings.Join(hostLabels[len(hostLabels)-len(rootLabels):], ".") != root {
		return nil, ""
	}
	for offset := 1; offset <= len(hostLabels)-len(rootLabels); offset++ {
		parent := strings.Join(hostLabels[offset:], ".")
		records, err := resolver.ResolveCAA(ctx, parent)
		if err != nil {
			return nil, ""
		}
		if len(records) > 0 {
			return records, parent
		}
	}
	return nil, ""
}

func caaPolicy(records []string) []string {
	seen := make(map[string]struct{})
	var policy []string
	for _, record := range records {
		fields := strings.Fields(strings.ToLower(strings.TrimSpace(record)))
		if len(fields) < 2 || (fields[0] != "issue" && fields[0] != "issuewild") {
			continue
		}
		issuer := strings.Trim(strings.SplitN(fields[1], ";", 2)[0], `"' `)
		value := fields[0] + "=" + issuer
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		policy = append(policy, value)
	}
	sort.Strings(policy)
	return policy
}

func caaIssuers(records []string, wildcard bool) ([]string, bool) {
	byTag := map[string][]string{"issue": {}, "issuewild": {}}
	present := make(map[string]bool)
	for _, record := range records {
		fields := strings.Fields(strings.ToLower(strings.TrimSpace(record)))
		if len(fields) < 2 || (fields[0] != "issue" && fields[0] != "issuewild") {
			continue
		}
		present[fields[0]] = true
		issuer := strings.Trim(strings.SplitN(fields[1], ";", 2)[0], `"' `)
		if issuer != "" && !containsCAA(byTag[fields[0]], issuer) {
			byTag[fields[0]] = append(byTag[fields[0]], issuer)
		}
	}
	tag := "issue"
	if wildcard && present["issuewild"] {
		tag = "issuewild"
	}
	sort.Strings(byTag[tag])
	return byTag[tag], present[tag]
}

func tlsIssuer(evidences []core.Evidence) string {
	for _, evidence := range evidences {
		if issuer := strings.TrimSpace(evidence.Metadata["tls_issuer"]); issuer != "" {
			return issuer
		}
	}
	return ""
}

func tlsHasWildcard(evidences []core.Evidence) bool {
	for _, evidence := range evidences {
		if strings.Contains(evidence.Metadata["tls_sans"], "*.") {
			return true
		}
	}
	return false
}

func issuerCAAName(issuer string) string {
	issuer = strings.ToLower(issuer)
	switch {
	case strings.Contains(issuer, "let's encrypt"), strings.Contains(issuer, "letsencrypt"):
		return "letsencrypt.org"
	case strings.Contains(issuer, "google trust"):
		return "pki.goog"
	case strings.Contains(issuer, "digicert"):
		return "digicert.com"
	case strings.Contains(issuer, "sectigo"), strings.Contains(issuer, "comodo"):
		return "sectigo.com"
	case strings.Contains(issuer, "amazon"):
		return "amazon.com"
	case strings.Contains(issuer, "globalsign"):
		return "globalsign.com"
	case strings.Contains(issuer, "zerossl"):
		return "zerossl.com"
	default:
		return ""
	}
}

func containsCAA(issuers []string, expected string) bool {
	for _, issuer := range issuers {
		if issuer == expected {
			return true
		}
	}
	return false
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
