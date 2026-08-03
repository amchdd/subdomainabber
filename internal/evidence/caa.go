package evidence

import (
	"context"
	"fmt"

	"github.com/amchdd/subdomainabber/internal/core"
)

// CAACollector analisa os registros CAA para injetar evidências de
// emissão restrita de certificados, o que pode mitigar certas
// vulnerabilidades de takeover.
type CAACollector struct{}

func NewCAACollector() *CAACollector {
	return &CAACollector{}
}

func (c *CAACollector) Collect(ctx context.Context, analysis *core.HostAnalysis) error {
	analysis.AddTestedVector("CAA")

	if len(analysis.DNS.CAA) == 0 {
		return nil
	}

	// Registros CAA fornecem contexto sobre a emissão autorizada de certificados.
	analysis.AddEvidence(core.Evidence{
		Type:        "CAA_RECORD_PRESENT",
		Source:      "DNS",
		Description: "O domínio possui registros CAA configurados, restringindo emissão de certificados",
		Weight:      10, // Aumenta o MitigationScore
		Confidence:  100,
		IsNegative:  true, // Mitigação
		Metadata: map[string]string{
			"caa_count": fmt.Sprintf("%d", len(analysis.DNS.CAA)),
		},
	})

	return nil
}
