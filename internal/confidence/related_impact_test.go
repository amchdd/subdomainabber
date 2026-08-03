package confidence

import (
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
)

func TestRelatedDomainImpactDoesNotInflateTakeoverConfidence(t *testing.T) {
	baseline := &core.HostAnalysis{
		Classification: "TAKEOVERABLE",
		Evidences: []core.Evidence{{
			Type: "CLAIM_SUCCESS", Weight: 80, Confidence: 90,
		}},
		TestedVectors: []string{"DNS", "HTTP", "TLS"},
	}
	withImpact := *baseline
	withImpact.ParentCookieScope = true
	withImpact.ParentCORSWildcard = true

	baselineVerdict := Calculate(baseline)
	impactVerdict := Calculate(&withImpact)
	if impactVerdict.Percentage != baselineVerdict.Percentage {
		t.Fatalf("impacto related-domain alterou confiança: sem=%.1f com=%.1f", baselineVerdict.Percentage, impactVerdict.Percentage)
	}
	if len(impactVerdict.Reasons) <= len(baselineVerdict.Reasons) {
		t.Fatalf("contexto de impacto não foi narrado: %#v", impactVerdict.Reasons)
	}
}
