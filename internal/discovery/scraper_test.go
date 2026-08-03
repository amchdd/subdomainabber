package discovery

import (
	"context"
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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
