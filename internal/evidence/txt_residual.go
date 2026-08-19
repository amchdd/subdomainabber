package evidence

import (
	"context"
	"fmt"
	"strings"

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
	id = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(id)), "-", "_")
	switch {
	case id == "aws", id == "amazon", id == "cloudfront", strings.HasPrefix(id, "aws_"), strings.HasPrefix(id, "amazon_"):
		return "aws"
	case id == "cloudflare", strings.HasPrefix(id, "cloudflare_"):
		return "cloudflare"
	case id == "fastly", strings.HasPrefix(id, "fastly_"):
		return "fastly"
	case id == "github", strings.HasPrefix(id, "github_"):
		return "github"
	case id == "google", strings.HasPrefix(id, "google_"):
		return "google"
	case id == "azure", id == "microsoft", strings.HasPrefix(id, "azure_"), strings.HasPrefix(id, "microsoft_"):
		return "microsoft"
	default:
		return id
	}
}
