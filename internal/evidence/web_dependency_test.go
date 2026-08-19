package evidence

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/pkg/signatures"
)

func TestWebDepsCorrelateCSPAndHTML(t *testing.T) {
	body := `<html><script src="https://static.example.test/app.js"></script><img src="//img.example.test/logo.png"></html>`
	observation := newHTTPObservation("https", http.StatusOK, http.Header{
		"Content-Security-Policy": []string{"default-src 'self'; script-src 'self' https://csp.example.test"},
	}, []byte(body), true, 0, "", "")
	analysis := &core.HostAnalysis{Host: "www.example.test"}
	analysis.SetHTTPObservation("https", observation)
	resolver := &fakeWebResolver{status: map[string]core.DNSStatus{
		"static.provider.test": core.DNSStatusNXDomain,
		"img.provider.test":    core.DNSStatusNoData,
		"csp.provider.test":    core.DNSStatusNXDomain,
	}, chains: map[string][]string{
		"static.example.test": {"static.provider.test"},
		"img.example.test":    {"img.provider.test"},
		"csp.example.test":    {"csp.provider.test"},
	}}
	collector := NewWebDependencyCollector(resolver, &http.Client{})
	collector.SetSignatures([]signatures.Fingerprint{{Service: "Provider Test", CNames: []string{"provider.test"}}})
	collector.SetAllowedHosts([]string{"static.example.test", "img.example.test", "csp.example.test"})

	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	for _, evidenceType := range []string{"CSP_DANGLING_DEPENDENCY", "SUBRESOURCE_DANGLING", "DEAD_ASSET_REFERENCE"} {
		if !hasEvidenceType(analysis.Evidences, evidenceType) {
			t.Fatalf("%s ausente: %+v", evidenceType, analysis.Evidences)
		}
	}
	if len(analysis.WebDependencies) != 3 {
		t.Fatalf("dependências estruturadas inesperadas: %+v", analysis.WebDependencies)
	}
}

func TestWebDepsFollowDeadAsset(t *testing.T) {
	body := `<script src="https://static.example.test/old.js"></script>`
	analysis := &core.HostAnalysis{Host: "www.example.test"}
	analysis.SetHTTPObservation("https", newHTTPObservation("https", http.StatusOK, nil, []byte(body), true, 0, "", ""))
	resolver := &fakeWebResolver{status: map[string]core.DNSStatus{"static.example.test": core.DNSStatusResolved}}
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusGone, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("gone")), Request: request}, nil
	})}
	collector := NewWebDependencyCollector(resolver, client)
	collector.SetAllowedHosts([]string{"static.example.test"})

	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if !hasEvidenceType(analysis.Evidences, "DEAD_ASSET_HTTP") {
		t.Fatalf("asset removido não detectado: %+v", analysis.Evidences)
	}
}

func TestWebDepsRejectBareNXDomain(t *testing.T) {
	body := `<script src="https://missing.example.test/app.js"></script>`
	analysis := &core.HostAnalysis{Host: "www.example.test"}
	analysis.SetHTTPObservation("https", newHTTPObservation("https", http.StatusOK, nil, []byte(body), true, 0, "", ""))
	resolver := &fakeWebResolver{status: map[string]core.DNSStatus{"missing.example.test": core.DNSStatusNXDomain}}
	collector := NewWebDependencyCollector(resolver, &http.Client{})
	collector.SetAllowedHosts([]string{"missing.example.test"})

	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if hasEvidenceType(analysis.Evidences, "SUBRESOURCE_DANGLING") || analysis.WebDependencies[0].Dangling {
		t.Fatalf("NXDOMAIN sem provedor foi tratado como órfão: %+v", analysis)
	}
}
