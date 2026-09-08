package evidence

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/amchdd/subdomainabber/internal/classification"
	"github.com/amchdd/subdomainabber/internal/core"
)

func TestHTTPSecurityHeadersModeDoesNotSendRedirectProbes(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()

	analysis := &core.HostAnalysis{
		Host: strings.TrimPrefix(server.URL, "http://"),
	}
	analysis.SetHTTPObservation("https", newHTTPObservation("https", http.StatusOK,
		http.Header{"Content-Type": {"text/html"}}, []byte("ok"), true, 0, "", ""))
	collector := NewHttpSecurityCollectorForChecks(true, false)
	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 {
		t.Fatalf("headers-only mode sent %d active redirect probes", requests.Load())
	}
	if !containsTestedVector(analysis.TestedVectors, "SEC_HEADERS") || containsTestedVector(analysis.TestedVectors, "OPEN_REDIRECT") {
		t.Fatalf("tested vectors = %#v", analysis.TestedVectors)
	}
}

func TestHTTPSecurityHeadersUsesHTTPSObservationWithoutExportedHeaders(t *testing.T) {
	analysis := &core.HostAnalysis{Host: "secure.example.com"}
	analysis.SetHTTPObservation("https", newHTTPObservation("https", http.StatusOK,
		http.Header{"Strict-Transport-Security": {"max-age=31536000"}, "Content-Type": {"text/html"}}, []byte("<!doctype html><html><body>ok</body></html>"), true, 0, "", ""))

	collector := NewHttpSecurityCollectorForChecks(true, false)
	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	classification.Process(analysis)
	if _, found := findEvidence(analysis, "HTTPS_HSTS_ABSENT"); found {
		t.Fatal("present HSTS was reported missing")
	}
	if evidence, found := findEvidence(analysis, "HTTPS_HSTS_PRESENT"); !found || evidence.Metadata["max_age"] != "31536000" {
		t.Fatalf("postura HSTS incompleta: %+v", evidence)
	}
	if _, found := findEvidence(analysis, "HTTPS_CSP_ABSENT"); !found {
		t.Fatal("missing CSP was not detected from the HTTPS baseline")
	}
}

func containsTestedVector(vectors []string, want string) bool {
	for _, vector := range vectors {
		if vector == want {
			return true
		}
	}
	return false
}

func TestRedirectProbeRequiresExactDestinationHost(t *testing.T) {
	if !redirectsToProbeHost("https://evil.com/callback") || !redirectsToProbeHost("//evil.com/path") {
		t.Fatal("exact probe destination was not recognized")
	}
	for _, location := range []string{
		"https://not-evil.com/",
		"https://evil.com.attacker.example/",
		"/login?next=https://evil.com",
		"://malformed",
	} {
		if redirectsToProbeHost(location) {
			t.Fatalf("false open-redirect destination match: %q", location)
		}
	}
}
