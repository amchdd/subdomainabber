package evidence

import (
	"context"
	"net/http"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
)

func TestPostureMissingUpgrade(t *testing.T) {
	analysis := &core.HostAnalysis{Host: "app.example.test"}
	analysis.SetHTTPObservation("http", newHTTPObservation("http", http.StatusOK, nil, []byte("http"), true, 0, "", ""))
	analysis.SetHTTPObservation("https", newHTTPObservation("https", http.StatusOK, nil, []byte("https"), true, 0, "", ""))

	if err := NewHTTPPostureCollector().Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if !hasEvidenceType(analysis.Evidences, "HTTP_HTTPS_REDIRECT_MISSING") {
		t.Fatalf("postura sem upgrade não detectada: %+v", analysis.Evidences)
	}
}

func TestPostureDowngrade(t *testing.T) {
	analysis := &core.HostAnalysis{Host: "app.example.test"}
	analysis.SetHTTPObservation("https", newHTTPObservation("https", http.StatusFound,
		http.Header{"Location": []string{"http://app.example.test/"}}, nil, true, 0, "", ""))

	if err := NewHTTPPostureCollector().Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if !hasEvidenceType(analysis.Evidences, "HTTPS_DOWNGRADE_REDIRECT") {
		t.Fatalf("downgrade não detectado: %+v", analysis.Evidences)
	}
}
