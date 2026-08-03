package evidence

import (
	"context"
	"sort"
	"strings"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/dns"
)

type DNSSECCollector struct {
	resolver dnssecResolver
}

type dnssecResolver interface {
	CheckDNSSEC(context.Context, string) (map[string]bool, error)
	FindAuthoritativeZone(context.Context, string) (dns.AuthoritativeZone, error)
}

func NewDNSSECCollector(resolver dnssecResolver) *DNSSECCollector {
	return &DNSSECCollector{resolver: resolver}
}

func (c *DNSSECCollector) Name() string {
	return "DNSSEC"
}

func (c *DNSSECCollector) Collect(ctx context.Context, analysis *core.HostAnalysis) error {
	analysis.AddTestedVector("DNSSEC")

	zone := ""
	if analysis.Delegation != nil {
		zone = analysis.Delegation.Zone
	}
	if zone == "" {
		zoneInfo, err := c.resolver.FindAuthoritativeZone(ctx, analysis.Host)
		if err != nil {
			return nil
		}
		zone = zoneInfo.Zone
	}

	results, err := c.resolver.CheckDNSSEC(ctx, zone)
	if err == nil {
		var observed []string
		metadata := map[string]string{"zone": zone, "chain_validation": "not_performed"}
		for recordType, present := range results {
			if present {
				observed = append(observed, recordType)
				metadata[strings.ToLower(recordType)] = "present"
			}
		}
		if len(observed) > 0 {
			sort.Strings(observed)
			analysis.AddEvidence(core.Evidence{
				Type:        "DNSSEC_ARTIFACTS_OBSERVED",
				Source:      "DNSSEC",
				Description: "Foram observados artefatos DNSSEC (" + strings.Join(observed, ", ") + "); a cadeia de confiança e as assinaturas não foram validadas.",
				Weight:      0,
				Confidence:  100,
				Metadata:    metadata,
			})
		}
	}
	return nil
}
