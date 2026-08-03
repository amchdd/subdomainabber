package evidence

import (
	"context"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/domainutil"
)

type ShadowITCollector struct{}

func NewShadowITCollector() *ShadowITCollector {
	return &ShadowITCollector{}
}

func (c *ShadowITCollector) Name() string {
	return "ShadowIT"
}

func (c *ShadowITCollector) Collect(ctx context.Context, analysis *core.HostAnalysis) error {
	analysis.AddTestedVector("SHADOW_IT")
	shadowDomains := []string{
		"adobemc.com",
		"threatmetrix.com",
		"akamai.net",
		"segment.com",
		"marketo.com",
		"hubspot.net",
	}

	for _, cname := range analysis.DNS.CNAME {
		for _, shadow := range shadowDomains {
			if domainutil.MatchDNSName(cname, shadow) {
				analysis.AddEvidence(core.Evidence{
					Type:        "SHADOW_IT_DETECTED",
					Source:      "ShadowIT",
					Description: "O CNAME aponta para um serviço SaaS de terceiros ou rastreador (" + shadow + "), indicando possível Shadow IT ou CNAME Cloaking.",
					Weight:      0,
					Confidence:  90,
					IsNegative:  false,
				})
			}
		}
	}

	return nil
}
