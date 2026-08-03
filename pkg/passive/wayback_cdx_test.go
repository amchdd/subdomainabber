package passive

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestWaybackCDXProvider_Enumerate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/cdx/search/cdx" {
			resumeKey := req.URL.Query().Get("resumeKey")
			if resumeKey == "" {
				_, _ = rw.Write([]byte("http://example.com/script.js 20210101000000\n"))
				_, _ = rw.Write([]byte("http://example.com/main.js 20210102000000\n"))
				_, _ = rw.Write([]byte("\nresumeKeyMockedValue"))
			} else {
				_, _ = rw.Write([]byte("http://example.com/second.js 20210103000000\n"))
			}
		} else if strings.Contains(req.URL.Path, "script.js") {
			_, _ = rw.Write([]byte(`var a = "api.example.com"; fetch("https://dev.example.com/data");`))
		} else if req.URL.Path == "/web/20210102000000if_/http://example.com/main.js" {
			_, _ = rw.Write([]byte(`// some script`))
		}
	}))
	defer server.Close()

	provider := &WaybackCDXProvider{
		Client:         server.Client(),
		BaseURL:        server.URL + "/cdx/search/cdx",
		ArchiveBaseURL: server.URL,
	}

	out := make(chan string, 10)
	if err := provider.Enumerate(context.Background(), "example.com", out); err != nil {
		t.Fatalf("a enumeração CDX falhou: %v", err)
	}
	close(out)

	var results []string
	for r := range out {
		results = append(results, r)
	}

	foundApi := false
	for _, r := range results {
		if r == "api.example.com" {
			foundApi = true
		}
	}

	if !foundApi {
		t.Error("esperava encontrar api.example.com no retrato JavaScript")
	}
}

func TestWaybackCDXReportsScannerError(t *testing.T) {
	oversizedLine := strings.Repeat("a", (1<<20)+1) + "\n"
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		response, _ := responseWithBody(http.StatusOK, oversizedLine)
		return response, nil
	})}
	provider := &WaybackCDXProvider{
		Client:  client,
		BaseURL: "https://cdx.invalid/search",
	}

	err := provider.Enumerate(context.Background(), "example.com", make(chan string, 1))
	if err == nil || !strings.Contains(err.Error(), "lendo resposta do índice CDX") {
		t.Fatalf("o erro do scanner foi ignorado: %v", err)
	}
}

func TestWaybackCDXRejectsOversizedSnapshotAndClosesBody(t *testing.T) {
	var snapshotBody *trackedBody
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "cdx.invalid" {
			response, _ := responseWithBody(http.StatusOK, "https://example.com/app.js 20260101000000\n")
			return response, nil
		}
		snapshotBody = &trackedBody{reader: &fixedSizeReader{remaining: maxWaybackSnapshotBytes + 1}}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       snapshotBody,
		}, nil
	})}
	provider := &WaybackCDXProvider{
		Client:         client,
		BaseURL:        "https://cdx.invalid/search",
		ArchiveBaseURL: "https://archive.invalid",
	}

	err := provider.Enumerate(context.Background(), "example.com", make(chan string, 1))
	if err == nil || !strings.Contains(err.Error(), "excedeu o limite") {
		t.Fatalf("o retrato acima do limite não foi reportado: %v", err)
	}
	if snapshotBody == nil || !snapshotBody.closed.Load() {
		t.Fatal("o corpo do retrato acima do limite não foi fechado")
	}
}

func TestWaybackCDXClosesUnsuccessfulSnapshotBody(t *testing.T) {
	var snapshotBody *trackedBody
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "cdx.invalid" {
			response, _ := responseWithBody(http.StatusOK, "https://example.com/ausente.js 20260101000000\n")
			return response, nil
		}
		response, body := responseWithBody(http.StatusNotFound, "ausente")
		snapshotBody = body
		return response, nil
	})}
	provider := &WaybackCDXProvider{
		Client:         client,
		BaseURL:        "https://cdx.invalid/search",
		ArchiveBaseURL: "https://archive.invalid",
	}

	err := provider.Enumerate(context.Background(), "example.com", make(chan string, 1))
	if err == nil || !strings.Contains(err.Error(), "retornou HTTP 404") {
		t.Fatalf("a falha do retrato não foi reportada: %v", err)
	}
	if snapshotBody == nil || !snapshotBody.closed.Load() {
		t.Fatal("o corpo do retrato malsucedido não foi fechado")
	}
}

func TestWaybackCDXRejectsRepeatedResumeKey(t *testing.T) {
	var requests atomic.Int64
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		response, _ := responseWithBody(http.StatusOK, "\ncursor-repetido")
		return response, nil
	})}
	provider := &WaybackCDXProvider{
		Client:  client,
		BaseURL: "https://cdx.invalid/search",
	}

	err := provider.Enumerate(context.Background(), "example.com", make(chan string, 1))
	if err == nil || !strings.Contains(err.Error(), "repetiu a chave de retomada") {
		t.Fatalf("a chave de retomada repetida não foi rejeitada: %v", err)
	}
	if requests.Load() != 2 {
		t.Fatalf("quantidade inesperada de páginas consultadas: %d", requests.Load())
	}
}

func TestWaybackCDXLimitsPagination(t *testing.T) {
	var requests atomic.Int64
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		current := requests.Add(1)
		response, _ := responseWithBody(http.StatusOK, fmt.Sprintf("\ncursor-%d", current))
		return response, nil
	})}
	provider := &WaybackCDXProvider{
		Client:  client,
		BaseURL: "https://cdx.invalid/search",
	}

	err := provider.Enumerate(context.Background(), "example.com", make(chan string, 1))
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("limite de %d páginas", maxWaybackCDXPages)) {
		t.Fatalf("o limite de páginas não foi aplicado: %v", err)
	}
	if requests.Load() != int64(maxWaybackCDXPages) {
		t.Fatalf("quantidade inesperada de páginas consultadas: %d", requests.Load())
	}
}

func TestWaybackCDXLimitsNumberOfSnapshots(t *testing.T) {
	var index strings.Builder
	for number := 0; number <= maxWaybackSnapshots; number++ {
		_, _ = fmt.Fprintf(&index, "https://example.com/%d.js 20260101000000\n", number)
	}
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "cdx.invalid" {
			response, _ := responseWithBody(http.StatusOK, index.String())
			return response, nil
		}
		response, _ := responseWithBody(http.StatusOK, "")
		return response, nil
	})}
	provider := &WaybackCDXProvider{
		Client:         client,
		BaseURL:        "https://cdx.invalid/search",
		ArchiveBaseURL: "https://archive.invalid",
	}

	err := provider.Enumerate(context.Background(), "example.com", make(chan string, 1))
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("limite de %d retratos", maxWaybackSnapshots)) {
		t.Fatalf("o limite de retratos não foi aplicado: %v", err)
	}
}
