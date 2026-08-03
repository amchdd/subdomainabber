package evidence

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/pkg/signatures"
)

func TestHTTPCollectorCombinesConfigurationErrorsWithoutExposingProxyCredentials(t *testing.T) {
	originalLoader := loadCDNSignatures
	loadCDNSignatures = func() ([]signatures.CDNSignature, error) {
		return nil, errors.New("catálogo CDN indisponível")
	}
	t.Cleanup(func() { loadCDNSignatures = originalLoader })

	collector := NewHTTPCollector(nil, time.Second, "ftp://usuario:segredo@proxy.example", false, "", false)
	err := collector.Validate()
	if err == nil {
		t.Fatal("uma configuração inválida foi aceita")
	}
	message := err.Error()
	for _, expected := range []string{"configurando proxy HTTP", "proxy inválido na posição 1", "carregando assinaturas CDN", "catálogo CDN indisponível"} {
		if !strings.Contains(message, expected) {
			t.Fatalf("erro não preservou %q: %q", expected, message)
		}
	}
	for _, secret := range []string{"usuario", "segredo"} {
		if strings.Contains(message, secret) {
			t.Fatalf("o erro expôs credenciais do proxy: %q", message)
		}
	}
}

func TestHTTPCollectorRejectsInvalidProxyBeforeAnyRequest(t *testing.T) {
	collector := NewHTTPCollector(nil, time.Second, "ftp://usuario:segredo@proxy.example", false, "", false)
	requests := 0
	collector.SetTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return nil, errors.New("requisição inesperada")
	}))
	analysis := &core.HostAnalysis{Host: "alvo.example", DNS: core.DNSRecordSet{A: []string{"192.0.2.1"}}}

	err := collector.Collect(context.Background(), analysis)
	if err == nil {
		t.Fatal("Collect aceitou um proxy inválido")
	}
	if requests != 0 {
		t.Fatalf("o coletor tentou %d requisição(ões) após rejeitar o proxy", requests)
	}
	if strings.Contains(err.Error(), "usuario") || strings.Contains(err.Error(), "segredo") {
		t.Fatalf("o erro expôs credenciais do proxy: %q", err)
	}
}

func TestHTTPCollectorInvalidProxyCannotFallBackToDirectTransport(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests++
	}))
	defer server.Close()

	collector := NewHTTPCollector(nil, time.Second, "ftp://usuario:segredo@proxy.example", false, "", false)
	request, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = collector.httpClient.Do(request)
	if err == nil {
		t.Fatal("o transporte aceitou uma configuração de proxy inválida")
	}
	if requests != 0 {
		t.Fatalf("o transporte fez %d conexão(ões) diretas", requests)
	}
	if strings.Contains(err.Error(), "usuario") || strings.Contains(err.Error(), "segredo") {
		t.Fatalf("o erro expôs credenciais do proxy: %q", err)
	}
}

func TestHTTPCollectorRejectsWhitespaceOnlyProxy(t *testing.T) {
	collector := NewHTTPCollector(nil, time.Second, "   ", false, "", false)
	if err := collector.Validate(); err == nil {
		t.Fatal("uma configuração de proxy composta apenas por espaços foi tratada como conexão direta")
	}
}

func TestHTTPCollectorDefaultUserAgentSendsConsistentClientHints(t *testing.T) {
	collector := NewHTTPCollector(nil, time.Second, "", false, "", false)
	var captured []http.Header
	collector.SetTransport(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		captured = append(captured, request.Header.Clone())
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("ok")),
			Request:    request,
		}, nil
	}))
	analysis := &core.HostAnalysis{Host: "alvo.example", DNS: core.DNSRecordSet{A: []string{"192.0.2.1"}}}

	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatalf("a coleta HTTP falhou: %v", err)
	}
	if len(captured) != 2 {
		t.Fatalf("requisições capturadas = %d; esperado 2", len(captured))
	}
	for _, header := range captured {
		userAgent := header.Get("User-Agent")
		platform := header.Get("Sec-CH-UA-Platform")
		brands := header.Get("Sec-CH-UA")
		if userAgent == "" || platform == "" || brands == "" || header.Get("Sec-CH-UA-Mobile") != "?0" {
			t.Fatalf("Client Hints incompletos para o User-Agent padrão: %#v", header)
		}
		if strings.Contains(userAgent, "Edg/") {
			if !strings.Contains(brands, `"Microsoft Edge"`) {
				t.Fatalf("marca incompatível com Edge: User-Agent=%q, Sec-CH-UA=%q", userAgent, brands)
			}
		} else if !strings.Contains(brands, `"Google Chrome"`) {
			t.Fatalf("marca incompatível com Chrome: User-Agent=%q, Sec-CH-UA=%q", userAgent, brands)
		}
	}
}

func TestHTTPCollectorCustomUserAgentOmitsUnverifiableClientHints(t *testing.T) {
	const customUserAgent = "scanner-autorizado/1.0"
	collector := NewHTTPCollector(nil, time.Second, "", false, customUserAgent, false)
	collector.SetTransport(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("User-Agent") != customUserAgent {
			t.Fatalf("User-Agent = %q", request.Header.Get("User-Agent"))
		}
		for _, name := range []string{"Sec-CH-UA", "Sec-CH-UA-Platform", "Sec-CH-UA-Mobile"} {
			if value := request.Header.Get(name); value != "" {
				t.Fatalf("%s inesperado para User-Agent personalizado: %q", name, value)
			}
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: request}, nil
	}))
	analysis := &core.HostAnalysis{Host: "alvo.example", DNS: core.DNSRecordSet{A: []string{"192.0.2.1"}}}
	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatalf("a coleta HTTP falhou: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestHTTPCollectorDoesNotMatchFingerprintOutsideProviderContext(t *testing.T) {
	collector := NewHTTPCollector([]signatures.Fingerprint{
		{
			Service:     "Cargo",
			CNames:      []string{"cargocollective.com"},
			Fingerprint: "404 Not Found",
			CheckType:   "cname",
			Vulnerable:  true,
		},
	}, 0, "", false, "test-agent", false)
	collector.SetTransport(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("404 Not Found")),
			Request:    request,
		}, nil
	}))

	analysis := &core.HostAnalysis{
		Host: "foo.example.com",
		DNS: core.DNSRecordSet{
			CNAME: []string{"user.github.io"},
			A:     []string{"192.0.2.1"},
		},
	}

	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatalf("Collect returned an unexpected error: %v", err)
	}
	for _, evidence := range analysis.Evidences {
		if evidence.Type == "HTTP_BODY_MATCH" && evidence.Source == "Cargo" {
			t.Fatal("Cargo fingerprint matched a response for an unrelated GitHub CNAME")
		}
	}
}

func TestHTTPCollectorKeepsGenericBoundFingerprintNeutral(t *testing.T) {
	collector := NewHTTPCollector([]signatures.Fingerprint{{Service: "Cargo", CNames: []string{"cargocollective.com"}, Fingerprint: "404 Not Found", CheckType: "cname", Vulnerable: true, Status: "Vulnerable"}}, 0, "", false, "test-agent", false)
	collector.SetTransport(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("404 Not Found")), Request: request}, nil
	}))
	analysis := &core.HostAnalysis{Host: "portfolio.example.com", DNS: core.DNSRecordSet{CNAME: []string{"user.cargocollective.com"}, A: []string{"192.0.2.1"}}}
	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if _, found := findEvidence(analysis, "HTTP_BODY_MATCH"); found {
		t.Fatal("generic provider-bound fingerprint became classifiable HTTP_BODY_MATCH")
	}
	if _, found := findEvidence(analysis, "HTTP_FINGERPRINT_REVIEW"); !found {
		t.Fatal("generic match was not retained for manual review")
	}
}

func TestHTTPCollectorRejectsFingerprintFromTruncatedBody(t *testing.T) {
	const fingerprint = "The specified bucket does not exist"
	collector := NewHTTPCollector([]signatures.Fingerprint{{
		Service: "AWS/S3", CNames: []string{"s3.amazonaws.com"}, Fingerprint: fingerprint,
		CheckType: "cname", Vulnerable: true,
	}}, time.Second, "", false, "agente-de-teste", false)
	collector.SetTransport(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := fingerprint + strings.Repeat("x", maxBodySize)
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    request,
		}, nil
	}))
	analysis := &core.HostAnalysis{
		Host: "bucket.example.com",
		DNS:  core.DNSRecordSet{CNAME: []string{"bucket.s3.amazonaws.com"}, A: []string{"192.0.2.1"}},
	}
	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatalf("a coleta HTTP falhou: %v", err)
	}
	if _, found := findEvidence(analysis, "HTTP_BODY_MATCH"); found {
		t.Fatal("um corpo truncado produziu uma assinatura elegível de takeover")
	}
	if _, found := findEvidence(analysis, "HTTP_FINGERPRINT_REVIEW"); found {
		t.Fatal("um corpo truncado produziu uma correspondência manual de assinatura")
	}
	for _, scheme := range []string{"http", "https"} {
		observation, ok := analysis.HTTPObservation(scheme)
		if !ok || observation.Complete || observation.ParseError == "" {
			t.Fatalf("observação %s não preservou o truncamento: %#v", scheme, observation)
		}
	}
}

func TestHTTPCollectorDoesNotFollowRedirectToAnotherHost(t *testing.T) {
	requests := 0
	collector := NewHTTPCollector(nil, time.Second, "", true, "agente-de-teste", false)
	collector.SetTransport(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{"https://fora.example.net/final"}},
			Body:       io.NopCloser(strings.NewReader("redirecionamento")),
			Request:    request,
		}, nil
	}))
	analysis := &core.HostAnalysis{Host: "alvo.example.com", DNS: core.DNSRecordSet{A: []string{"192.0.2.1"}}}
	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatalf("a coleta HTTP falhou: %v", err)
	}
	if requests != 2 {
		t.Fatalf("o redirecionamento para outro host foi seguido: requisições=%d", requests)
	}
}

func TestHTTPCollectorFollowsRedirectOnSameHost(t *testing.T) {
	requests := 0
	collector := NewHTTPCollector(nil, time.Second, "", true, "agente-de-teste", false)
	collector.SetTransport(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.URL.Path != "/final" {
			return &http.Response{
				StatusCode: http.StatusFound,
				Header:     http.Header{"Location": []string{"/final"}},
				Body:       io.NopCloser(strings.NewReader("redirecionamento")),
				Request:    request,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("resposta final")),
			Request:    request,
		}, nil
	}))
	analysis := &core.HostAnalysis{Host: "alvo.example.com", DNS: core.DNSRecordSet{A: []string{"192.0.2.1"}}}
	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatalf("a coleta HTTP falhou: %v", err)
	}
	if requests != 4 {
		t.Fatalf("o redirecionamento no mesmo host não foi seguido: requisições=%d", requests)
	}
}
