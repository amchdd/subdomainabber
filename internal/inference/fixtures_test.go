package inference_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/amchdd/subdomainabber/internal/classification"
	"github.com/amchdd/subdomainabber/internal/core"
)

type regressionFixture struct {
	Cases []struct {
		Name      string            `json:"name"`
		Analysis  core.HostAnalysis `json:"analysis"`
		Class     string            `json:"expected_classification"`
		State     core.ResultState  `json:"expected_state"`
		Required  string            `json:"required_evidence,omitempty"`
		Forbidden string            `json:"forbidden_evidence,omitempty"`
	} `json:"cases"`
}

func TestHTTPRegressionFixtures(t *testing.T) {
	data, err := os.ReadFile("testdata/http_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture regressionFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for index := range fixture.Cases {
		entry := &fixture.Cases[index]
		t.Run(entry.Name, func(t *testing.T) {
			classification.Process(&entry.Analysis)
			if entry.Analysis.Classification != entry.Class || entry.Analysis.ResultState != entry.State {
				t.Fatalf("resultado = %s/%s, esperado %s/%s", entry.Analysis.Classification, entry.Analysis.ResultState, entry.Class, entry.State)
			}
			if entry.Required != "" && !hasEvidence(&entry.Analysis, entry.Required) {
				t.Fatalf("evidência %s ausente: %+v", entry.Required, entry.Analysis.Evidences)
			}
			if entry.Forbidden != "" && hasEvidence(&entry.Analysis, entry.Forbidden) {
				t.Fatalf("evidência %s não deveria existir: %+v", entry.Forbidden, entry.Analysis.Evidences)
			}
		})
	}
}
