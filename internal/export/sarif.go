package export

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/amchdd/subdomainabber/internal/classification"
	"github.com/amchdd/subdomainabber/internal/core"
)

type SARIFExporter struct {
	file string
}

func NewSARIFExporter(file string) *SARIFExporter {
	return &SARIFExporter{file: file}
}

func (exporter *SARIFExporter) Export(ctx context.Context, hosts []core.HostAnalysis) error {
	document := buildSARIF(hosts)
	out := os.Stdout
	if exporter.file != "" {
		file, err := os.Create(exporter.file)
		if err != nil {
			return fmt.Errorf("criando arquivo SARIF: %w", err)
		}
		defer file.Close()
		out = file
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(document)
}

type sarifDocument struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	ShortDescription sarifMessage `json:"shortDescription"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

func buildSARIF(hosts []core.HostAnalysis) sarifDocument {
	ruleSet := make(map[string]struct{})
	var results []sarifResult
	for _, host := range hosts {
		if !sarifActionable(host.Classification) {
			continue
		}
		ruleSet[host.Classification] = struct{}{}
		message := fmt.Sprintf("%s foi classificado como %s", host.Host, host.Classification)
		results = append(results, sarifResult{
			RuleID: host.Classification, Level: sarifLevel(host.Classification), Message: sarifMessage{Text: message},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: "https://" + host.Host}}}},
		})
	}
	ids := make([]string, 0, len(ruleSet))
	for id := range ruleSet {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rules := make([]sarifRule, 0, len(ids))
	for _, id := range ids {
		rules = append(rules, sarifRule{ID: id, ShortDescription: sarifMessage{Text: "Classificação " + id}})
	}
	return sarifDocument{
		Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{Tool: sarifTool{Driver: sarifDriver{Name: "SubdomainAbber", Rules: rules}}, Results: results}},
	}
}

func sarifActionable(level string) bool {
	return level != "" && level != classification.LevelHealthy && level != classification.LevelUnknown && level != classification.LevelInsufficientEvidence
}

func sarifLevel(level string) string {
	switch level {
	case classification.LevelTakenOver, classification.LevelZoneControlConfirmed, classification.LevelConfirmed,
		classification.LevelTakeoverable, classification.LevelDelegationClaimabilityVerified:
		return "error"
	case classification.LevelLikelyTakeoverable, classification.LevelDelegationTakeoverCandidate, classification.LevelExposed:
		return "warning"
	default:
		return "note"
	}
}
