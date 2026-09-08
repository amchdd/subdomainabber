package evidence

import (
	"context"
	"net/http"
	"testing"

	"github.com/amchdd/subdomainabber/internal/classification"
	"github.com/amchdd/subdomainabber/internal/core"
)

func TestPostureMissingUpgrade(t *testing.T) {
	analysis := &core.HostAnalysis{Host: "app.example.test"}
	analysis.SetHTTPObservation("http", newHTTPObservation("http", http.StatusOK, nil, []byte("http"), true, 0, "", ""))
	analysis.SetHTTPObservation("https", newHTTPObservation("https", http.StatusOK, nil, []byte("https"), true, 0, "", ""))

	if err := NewHTTPPostureCollector().Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	classification.Process(analysis)
	if !hasEvidenceType(analysis.Evidences, "HTTP_NO_HTTPS_UPGRADE") {
		t.Fatalf("postura sem upgrade não detectada: %+v", analysis.Evidences)
	}
}

func TestPostureAcceptsCanonicalHTTPSRedirect(t *testing.T) {
	analysis := &core.HostAnalysis{Host: "example.test"}
	analysis.SetHTTPObservation("http", newHTTPObservation("http", http.StatusMovedPermanently,
		http.Header{"Location": []string{"https://www.example.test/"}}, nil, true, 0, "", ""))
	analysis.SetHTTPObservation("https", newHTTPObservation("https", http.StatusOK, nil, nil, true, 0, "", ""))

	if err := NewHTTPPostureCollector().Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	classification.Process(analysis)
	if hasEvidenceType(analysis.Evidences, "HTTP_NO_HTTPS_UPGRADE") {
		t.Fatalf("upgrade para hostname canônico foi marcado como ausente: %+v", analysis.Evidences)
	}
}

func TestPostureAcceptsHTTPSAtEndOfChain(t *testing.T) {
	analysis := &core.HostAnalysis{Host: "app.example.test"}
	analysis.SetHTTPObservation("http", newHTTPObservation("http", http.StatusFound,
		http.Header{"Location": []string{"/login"}}, nil, true, 0, "", ""))
	analysis.SetHTTPObservation("https", newHTTPObservation("https", http.StatusOK, nil, nil, true, 0, "", ""))
	analysis.SetRedirectChain("http", core.RedirectChain{
		Scheme: "http", FinalURL: "https://app.example.test/login", StoppedReason: "FINAL_RESPONSE",
		Hops: []core.RedirectHop{{URL: "https://app.example.test/login", Scheme: "https", StatusCode: 200}},
	})

	if err := NewHTTPPostureCollector().Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	classification.Process(analysis)
	if hasEvidenceType(analysis.Evidences, "HTTP_NO_HTTPS_UPGRADE") {
		t.Fatalf("upgrade concluído na cadeia foi marcado como ausente: %+v", analysis.Evidences)
	}
}

func TestPostureDowngrade(t *testing.T) {
	analysis := &core.HostAnalysis{Host: "app.example.test"}
	analysis.SetHTTPObservation("https", newHTTPObservation("https", http.StatusFound,
		http.Header{"Location": []string{"http://app.example.test/"}}, nil, true, 0, "", ""))

	if err := NewHTTPPostureCollector().Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	classification.Process(analysis)
	if !hasEvidenceType(analysis.Evidences, "HTTPS_DOWNGRADE_REDIRECT") {
		t.Fatalf("downgrade não detectado: %+v", analysis.Evidences)
	}
}
