package evidence

import (
	"context"
	"sort"
	"strings"

	"github.com/amchdd/subdomainabber/internal/core"
)

type ProviderHistoryCollector struct{}

func NewProviderHistoryCollector() *ProviderHistoryCollector { return &ProviderHistoryCollector{} }

func (*ProviderHistoryCollector) Phase() CollectorPhase { return PhaseImpact }

func (*ProviderHistoryCollector) Collect(_ context.Context, analysis *core.HostAnalysis) error {
	if analysis.ScanProfile == nil || analysis.ScanProfile.Version < 2 {
		return nil
	}
	analysis.AddTestedVector("PROVIDER_HISTORY")
	previous := providerHistory(analysis.PreviousEvidences)
	current := providerHistory(analysis.Evidences)
	for vector, old := range previous {
		present := current[vector]
		if len(old) == 0 || len(present) == 0 || sameProviders(old, present) {
			continue
		}
		typeName := "PROVIDER_MIGRATION_DETECTED"
		description := "O provedor observado mudou desde a última varredura."
		if sharesProvider(old, present) {
			typeName = "PROVIDER_MIGRATION_STALE_REFERENCE"
			description = "A referência ao provedor anterior permanece junto ao provedor atual."
		}
		analysis.AddEvidence(core.Evidence{
			Type: typeName, Source: "HISTORY", Description: description,
			Weight: 0, Confidence: 90,
			Metadata: map[string]string{"vector": vector, "previous": strings.Join(old, ","), "current": strings.Join(present, ",")},
		})
	}
	return nil
}

func providerHistory(evidences []core.Evidence) map[string][]string {
	result := make(map[string][]string)
	for _, evidence := range evidences {
		vector := providerVector(evidence.Type)
		if vector == "" {
			continue
		}
		id := evidence.Metadata["provider_id"]
		if id == "" {
			id = providerID(evidence.Source)
		}
		if id != "" && !hasProvider(result[vector], id) {
			result[vector] = append(result[vector], id)
		}
	}
	for vector := range result {
		sort.Strings(result[vector])
	}
	return result
}

func providerVector(evidenceType string) string {
	switch evidenceType {
	case "CNAME_PROVIDER_MATCH":
		return "CNAME"
	case "MX_PROVIDER_MATCH":
		return "MX"
	case "SRV_PROVIDER_MATCH":
		return "SRV"
	case "TLS_PROVIDER_MATCH":
		return "TLS"
	case "CLOUD_IP_CONTEXT":
		return "IP"
	default:
		return ""
	}
}

func hasProvider(ids []string, expected string) bool {
	for _, id := range ids {
		if id == expected {
			return true
		}
	}
	return false
}

func sharesProvider(left, right []string) bool {
	for _, id := range left {
		if hasProvider(right, id) {
			return true
		}
	}
	return false
}

func sameProviders(left, right []string) bool {
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
