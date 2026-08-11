package evidence

import (
	"context"
	"fmt"

	"github.com/amchdd/subdomainabber/internal/core"
)

type TXTResidualCollector struct{}

func NewTXTResidualCollector() *TXTResidualCollector { return &TXTResidualCollector{} }

func (*TXTResidualCollector) Phase() CollectorPhase { return PhaseImpact }

func (*TXTResidualCollector) Collect(_ context.Context, analysis *core.HostAnalysis) error {
	active := make(map[string]bool)
	for _, candidate := range analysis.ProviderCandidateSnapshot() {
		family := providerFamily(candidate.ProviderID)
		if candidate.Vector != "TXT" && family != "" {
			active[family] = true
		}
	}
	for index := range analysis.TXTCandidates {
		candidate := &analysis.TXTCandidates[index]
		id := providerFamily(providerID(candidate.Provider))
		if active[id] {
			candidate.State = "RELATED_PROVIDER_PRESENT"
			continue
		}
		candidate.State = "POSSIBLY_RESIDUAL"
		analysis.AddEvidence(core.Evidence{
			Type: "TXT_OWNERSHIP_TOKEN_RESIDUAL", Source: candidate.Provider,
			Description: fmt.Sprintf("Token de propriedade de %s sem outro vínculo observado; o estado residual não comprova exploração.", candidate.Provider),
			Weight:      0, Confidence: 70,
			Metadata: map[string]string{"state": candidate.State, "token_prefix": candidate.TokenPrefix},
		})
	}
	return nil
}

func providerFamily(id string) string {
	switch id {
	case "github", "github_pages":
		return "github"
	case "google", "google_workspace":
		return "google"
	case "microsoft_365", "microsoft_azure", "microsoft_entra_id", "microsoft_intune":
		return "microsoft"
	default:
		return id
	}
}
