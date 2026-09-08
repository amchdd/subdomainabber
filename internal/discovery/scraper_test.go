package discovery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func TestSubdomainRegexPreservesNestedHost(t *testing.T) {
	matches := SubdomainRegex("example.com").FindAllString("https://api.dev.example.com./v1", -1)
	if !reflect.DeepEqual(matches, []string{"api.dev.example.com."}) {
		t.Fatalf("subdomínio aninhado não foi preservado: %#v", matches)
	}
}

func TestSubdomainRegexRejectsInvalidBaseDomain(t *testing.T) {
	if SubdomainRegex("example..com").MatchString("api.example.com") {
		t.Fatal("domínio base inválido gerou correspondência")
	}
}

func TestScrapePageUsesProvidedClient(t *testing.T) {
	var calls atomic.Int64
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("api.dev.example.com api.example.com.")),
			Header:     make(http.Header),
			Request:    request,
		}, nil
	})}

	got, err := ScrapePage(context.Background(), "https://source.example", "example.com", client)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"api.dev.example.com", "api.example.com"}
	if !reflect.DeepEqual(got, want) || calls.Load() != 1 {
		t.Fatalf("resultado inesperado: got=%#v calls=%d", got, calls.Load())
	}
}

func TestScrapePageAppliesProgramHeaders(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("User-Agent") != "Researcher" || request.Header.Get("X-Research") != "yes" {
			t.Fatalf("headers do programa ausentes: %#v", request.Header)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("api.example.com")),
			Header:     make(http.Header),
			Request:    request,
		}, nil
	})}
	headers := http.Header{"User-Agent": {"Researcher"}, "X-Research": {"yes"}}
	if _, err := ScrapePageWithHeaders(context.Background(), "https://source.example", "example.com", headers, client); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultScraperClientDoesNotFollowExternalRedirect(t *testing.T) {
	var externalCalls atomic.Int64
	external := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		externalCalls.Add(1)
	}))
	defer external.Close()

	source := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, strings.Replace(external.URL, "127.0.0.1", "localhost", 1), http.StatusFound)
	}))
	defer source.Close()

	got, err := ScrapePage(context.Background(), source.URL, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 || externalCalls.Load() != 0 {
		t.Fatalf("redirecionamento externo foi seguido: got=%#v calls=%d", got, externalCalls.Load())
	}
}

func TestScrapePageCollectsSANEvenWhenHTTPIsBlocked(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("bloqueado")),
			TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{
				DNSNames: []string{"api.example.test", "fora.invalid", "*.example.test"},
			}}},
		}, nil
	})}
	names, err := ScrapePage(context.Background(), "https://example.test", "example.test", client)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "api.example.test" {
		t.Fatalf("SANs inesperados: %v", names)
	}
}

func TestCrawlPageFollowsOnlySameOriginAssets(t *testing.T) {
	var externalRequests atomic.Int32
	external := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		externalRequests.Add(1)
	}))
	defer external.Close()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/app.js" {
			_, _ = writer.Write([]byte(`fetch("https://api.example.test/v1")`))
			return
		}
		_, _ = writer.Write([]byte(`<script src="/app.js"></script><script src="` + external.URL + `/external.js"></script>`))
	}))
	defer server.Close()

	references, err := crawlReferences(context.Background(), server.URL, "example.test", nil, 4, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if externalRequests.Load() != 0 {
		t.Fatalf("asset externo foi consultado %d vez(es)", externalRequests.Load())
	}
	found := false
	for _, reference := range references {
		if reference.name == "api.example.test" && reference.method == "script" {
			found = true
		}
	}
	if !found {
		t.Fatalf("referência do script não encontrada: %+v", references)
	}
}

func TestAssetRedirectOrigin(t *testing.T) {
	var externalRequests atomic.Int32
	external := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		externalRequests.Add(1)
	}))
	defer external.Close()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/app.js":
			http.Redirect(writer, request, "/bundle.js", http.StatusFound)
		case "/bundle.js":
			_, _ = writer.Write([]byte(`"https://api.example.test"`))
		case "/external.js":
			http.Redirect(writer, request, external.URL, http.StatusFound)
		default:
			_, _ = writer.Write([]byte(`<script src="/app.js"></script><script src="/external.js"></script>`))
		}
	}))
	defer server.Close()
	client := server.Client()
	references, err := crawlReferences(context.Background(), server.URL, "example.test", nil, 4, client)
	if err != nil {
		t.Fatal(err)
	}
	if externalRequests.Load() != 0 || client.CheckRedirect != nil {
		t.Fatal("o asset saiu da origem ou alterou o cliente compartilhado")
	}
	if len(references) != 1 || references[0].name != "api.example.test" {
		t.Fatalf("redirect interno não preservou a coleta: %+v", references)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
