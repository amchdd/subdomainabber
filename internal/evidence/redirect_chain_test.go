package evidence

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
)

type fakeWebResolver struct {
	chains map[string][]string
	status map[string]core.DNSStatus
	calls  []string
}

func (resolver *fakeWebResolver) ResolveCNAMEChain(_ context.Context, host string) ([]string, error) {
	return append([]string(nil), resolver.chains[host]...), nil
}

func (resolver *fakeWebResolver) ResolveAddressStatus(_ context.Context, host string) core.DNSStatus {
	resolver.calls = append(resolver.calls, host)
	if status, ok := resolver.status[host]; ok {
		return status
	}
	return core.DNSStatusResolved
}

func TestRedirectRecordsHops(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		status, location, body := http.StatusOK, "", "final"
		switch request.URL.Path {
		case "/":
			status, location, body = http.StatusFound, "/one", ""
		case "/one":
			status, location, body = http.StatusTemporaryRedirect, "/final", ""
		}
		return webResponse(request, status, location, body), nil
	})}
	analysis := &core.HostAnalysis{Host: "app.example.test"}
	analysis.SetHTTPObservation("https", newHTTPObservation("https", http.StatusFound, http.Header{"Location": []string{"/one"}}, nil, true, 0, "", ""))

	collector := NewRedirectCollector(&fakeWebResolver{}, client, 5)
	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}

	chain, ok := analysis.Redirects["https"]
	if !ok || len(chain.Hops) != 3 || chain.FinalURL != "https://app.example.test/final" {
		t.Fatalf("cadeia inesperada: %+v", chain)
	}
	if countEvidence(analysis, "HTTP_REDIRECT_HOP") != 3 {
		t.Fatalf("cada hop deveria ter evidência: %+v", analysis.Evidences)
	}
}

func TestRedirectFindsDanglingTarget(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return webResponse(request, http.StatusMovedPermanently, "https://missing.example.test/final", ""), nil
	})}
	resolver := &fakeWebResolver{status: map[string]core.DNSStatus{"missing.example.test": core.DNSStatusNXDomain}}
	analysis := &core.HostAnalysis{Host: "app.example.test"}
	analysis.SetHTTPObservation("http", newHTTPObservation("http", http.StatusMovedPermanently, nil, nil, true, 0, "", ""))
	collector := NewRedirectCollector(resolver, client, 5)
	collector.SetAllowedHosts([]string{"missing.example.test"})

	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if !hasEvidenceType(analysis.Evidences, "DANGLING_REDIRECT") {
		t.Fatalf("destino dangling não detectado: %+v", analysis.Evidences)
	}
}

func TestRedirectFindsRemovedResource(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/" {
			return webResponse(request, http.StatusFound, "/removed", ""), nil
		}
		return webResponse(request, http.StatusGone, "", "gone"), nil
	})}
	analysis := &core.HostAnalysis{Host: "app.example.test"}
	analysis.SetHTTPObservation("https", newHTTPObservation("https", http.StatusFound, nil, nil, true, 0, "", ""))

	if err := NewRedirectCollector(&fakeWebResolver{}, client, 5).Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if !hasEvidenceType(analysis.Evidences, "DANGLING_REDIRECT") {
		t.Fatalf("recurso removido não detectado: %+v", analysis.Evidences)
	}
}

func TestRedirectStopsOutsideScope(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return webResponse(request, http.StatusFound, "https://outside.example.net/", ""), nil
	})}
	resolver := &fakeWebResolver{}
	analysis := &core.HostAnalysis{Host: "app.example.test"}
	analysis.SetHTTPObservation("https", newHTTPObservation("https", http.StatusFound, nil, nil, true, 0, "", ""))
	collector := NewRedirectCollector(resolver, client, 5)

	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if len(resolver.calls) != 0 || !hasEvidenceType(analysis.Evidences, "REDIRECT_TARGET_OUT_OF_SCOPE") {
		t.Fatalf("destino externo não foi bloqueado: chamadas=%v evidências=%+v", resolver.calls, analysis.Evidences)
	}
}

func webResponse(request *http.Request, status int, location, body string) *http.Response {
	header := make(http.Header)
	if location != "" {
		header.Set("Location", location)
	}
	return &http.Response{
		StatusCode: status,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}
}

func countEvidence(analysis *core.HostAnalysis, evidenceType string) int {
	count := 0
	for _, evidence := range analysis.Evidences {
		if evidence.Type == evidenceType {
			count++
		}
	}
	return count
}
