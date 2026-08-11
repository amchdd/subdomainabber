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
	hostPolicy := caaIssuers(analysis.DNS.CAA)
	root := dns.ExtractRootDomain(analysis.Host)
	var zonePolicy []string
	if collector.resolver != nil && root != "" && !strings.EqualFold(root, analysis.Host) {
		if records, err := collector.resolver.ResolveCAA(ctx, root); err == nil {
			zonePolicy = caaIssuers(records)
		}
	}
	effective := hostPolicy
	if len(effective) == 0 {
		effective = zonePolicy
	}
	if len(effective) > 0 {
		analysis.AddEvidence(core.Evidence{
			Type: "CAA_RECORD_PRESENT", Source: "DNS",
			Description: "A política CAA restringe as autoridades certificadoras permitidas.",
			Weight:      10, Confidence: 100, IsNegative: true,
			Metadata: map[string]string{"issuers": strings.Join(effective, ","), "zone": root},
		})
	}
	if len(hostPolicy) > 0 && len(zonePolicy) > 0 && !sameStrings(hostPolicy, zonePolicy) {
		analysis.AddEvidence(core.Evidence{
			Type: "CAA_POLICY_INCONSISTENT", Source: "DNS",
			Description: "As políticas CAA do hostname e da zona registrável são diferentes.",
			Weight:      0, Confidence: 100,
			Metadata: map[string]string{"host_issuers": strings.Join(hostPolicy, ","), "zone_issuers": strings.Join(zonePolicy, ","), "zone": root},
		})
	}
	issuer := tlsIssuer(analysis.Evidences)
	issuerDomain := issuerCAAName(issuer)
	if issuerDomain != "" && len(effective) > 0 && !containsCAA(effective, issuerDomain) {
		analysis.AddEvidence(core.Evidence{
			Type: "CAA_ISSUER_MISMATCH", Source: "DNS/TLS",
			Description: fmt.Sprintf("O certificado observado foi emitido por %s, fora da política CAA coletada.", issuer),
			Weight:      0, Confidence: 90,
			Metadata: map[string]string{"tls_issuer": issuer, "issuer_domain": issuerDomain, "allowed_issuers": strings.Join(effective, ",")},
		})
	}
	return nil
}

func caaIssuers(records []string) []string {
	seen := make(map[string]struct{})
	var issuers []string
	for _, record := range records {
		fields := strings.Fields(strings.ToLower(strings.TrimSpace(record)))
		if len(fields) < 2 || (fields[0] != "issue" && fields[0] != "issuewild") {
			continue
		}
		issuer := strings.Trim(strings.SplitN(fields[1], ";", 2)[0], `"' `)
		if issuer == "" {
			continue
		}
		if _, ok := seen[issuer]; ok {
			continue
		}
		seen[issuer] = struct{}{}
		issuers = append(issuers, issuer)
	}
	sort.Strings(issuers)
	return issuers
}

func tlsIssuer(evidences []core.Evidence) string {
	for _, evidence := range evidences {
		if issuer := strings.TrimSpace(evidence.Metadata["tls_issuer"]); issuer != "" {
			return issuer
		}
	}
	return ""
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
		if issuer == expected || strings.HasSuffix(issuer, "."+expected) {
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
