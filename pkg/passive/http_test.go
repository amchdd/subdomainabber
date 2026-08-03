package passive

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type recordingTransport struct {
	function roundTripFunc
}

func (transport *recordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport.function(request)
}

type trackedBody struct {
	reader io.Reader
	closed atomic.Bool
}

func (body *trackedBody) Read(buffer []byte) (int, error) {
	return body.reader.Read(buffer)
}

func (body *trackedBody) Close() error {
	body.closed.Store(true)
	return nil
}

type fixedSizeReader struct {
	remaining int64
}

func (reader *fixedSizeReader) Read(buffer []byte) (int, error) {
	if reader.remaining == 0 {
		return 0, io.EOF
	}
	amount := int64(len(buffer))
	if amount > reader.remaining {
		amount = reader.remaining
	}
	for index := int64(0); index < amount; index++ {
		buffer[index] = 'x'
	}
	reader.remaining -= amount
	return int(amount), nil
}

func responseWithBody(status int, content string) (*http.Response, *trackedBody) {
	body := &trackedBody{reader: strings.NewReader(content)}
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       body,
	}, body
}

func TestPassiveHTTPClientBlocksCrossOriginRedirect(t *testing.T) {
	var targetRequests atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		targetRequests.Add(1)
		_, _ = writer.Write([]byte("conteúdo externo"))
	}))
	defer target.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Redirect(writer, &http.Request{}, target.URL, http.StatusFound)
	}))
	defer origin.Close()

	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, origin.URL, nil)
	if err != nil {
		t.Fatalf("criando requisição de teste: %v", err)
	}
	response, err := passiveHTTPClient(origin.Client()).Do(request)
	if err != nil {
		t.Fatalf("a resposta ao redirecionamento deveria ser devolvida sem segui-lo: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusFound {
		t.Fatalf("status inesperado: obtido %d, esperado %d", response.StatusCode, http.StatusFound)
	}
	if targetRequests.Load() != 0 {
		t.Fatalf("o cliente seguiu %d redirecionamento(s) para outra origem", targetRequests.Load())
	}
}

func TestPassiveHTTPClientPreservesInjectedTransportAndRedirectPolicy(t *testing.T) {
	expected := errors.New("política compartilhada")
	transport := &recordingTransport{function: func(*http.Request) (*http.Response, error) {
		response, _ := responseWithBody(http.StatusOK, "[]")
		return response, nil
	}}
	shared := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return expected
		},
	}
	client := passiveHTTPClient(shared)
	if client.Transport != transport {
		t.Fatal("o transporte do cliente compartilhado não foi preservado")
	}

	initial, _ := url.Parse("https://fonte.invalid/inicial")
	next, _ := url.Parse("https://fonte.invalid/seguinte")
	err := client.CheckRedirect(&http.Request{URL: next}, []*http.Request{{URL: initial}})
	if !errors.Is(err, expected) {
		t.Fatalf("a política de redirecionamento injetada não foi preservada: %v", err)
	}
}

func TestFetchLimitedRejectsOversizedResponseAndClosesBody(t *testing.T) {
	body := &trackedBody{reader: &fixedSizeReader{remaining: maxPassiveAPIResponseBytes + 1}}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       body,
		}, nil
	})}
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://fonte.invalid", nil)

	_, err := fetchLimited(client, request, "fonte de teste", maxPassiveAPIResponseBytes)
	if err == nil || !strings.Contains(err.Error(), "excedeu o limite") {
		t.Fatalf("resposta acima do limite aceita: %v", err)
	}
	if !body.closed.Load() {
		t.Fatal("o corpo da resposta acima do limite não foi fechado")
	}
}

func TestFetchLimitedClosesBodyOnHTTPError(t *testing.T) {
	response, body := responseWithBody(http.StatusServiceUnavailable, "indisponível")
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response, nil
	})}
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://fonte.invalid", nil)

	_, err := fetchLimited(client, request, "fonte de teste", 1024)
	if err == nil || !strings.Contains(err.Error(), "retornou HTTP 503") {
		t.Fatalf("erro HTTP sem mensagem adequada: %v", err)
	}
	if !body.closed.Load() {
		t.Fatal("o corpo da resposta HTTP malsucedida não foi fechado")
	}
}

func TestFetchLimitedDoesNotExposeRequestURLInTransportError(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return nil, &url.Error{
			Op:  request.Method,
			URL: request.URL.String(),
			Err: errors.New("falha simulada"),
		}
	})}
	request, _ := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"https://archive.invalid/retrato.js?token=segredo",
		nil,
	)

	_, err := fetchLimited(client, request, "retrato da Wayback Machine", 1024)
	if err == nil || !strings.Contains(err.Error(), "falha simulada") {
		t.Fatalf("erro de transporte inesperado: %v", err)
	}
	if strings.Contains(err.Error(), "segredo") || strings.Contains(err.Error(), "archive.invalid") {
		t.Fatalf("o erro expôs a URL consultada: %v", err)
	}
}

func TestPassiveProvidersUseInjectedClientAndCloseBodies(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		provider Provider
	}{
		{name: "crt.sh", payload: `[]`, provider: &CrtshProvider{}},
		{name: "Wayback Machine", payload: `[["urlkey","timestamp","original"]]`, provider: &WaybackProvider{}},
		{name: "AlienVault OTX", payload: `{}`, provider: &AlienVaultProvider{}},
		{name: "CertSpotter", payload: `[]`, provider: &CertSpotterProvider{}},
		{name: "urlscan.io", payload: `{"results":[],"has_more":false}`, provider: &URLScanProvider{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var called atomic.Bool
			var body *trackedBody
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				called.Store(true)
				response, responseBody := responseWithBody(http.StatusOK, test.payload)
				body = responseBody
				return response, nil
			})}

			switch provider := test.provider.(type) {
			case *CrtshProvider:
				provider.Client = client
			case *WaybackProvider:
				provider.Client = client
			case *AlienVaultProvider:
				provider.Client = client
			case *CertSpotterProvider:
				provider.Client = client
			case *URLScanProvider:
				provider.Client = client
			}

			if err := test.provider.Enumerate(context.Background(), "example.com", make(chan string, 4)); err != nil {
				t.Fatalf("o provedor falhou: %v", err)
			}
			if !called.Load() {
				t.Fatal("o cliente HTTP injetado não foi usado")
			}
			if body == nil || !body.closed.Load() {
				t.Fatal("o corpo da resposta não foi fechado")
			}
		})
	}
}

func TestCrtshReportsMalformedJSONInPortuguese(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		response, _ := responseWithBody(http.StatusOK, "{")
		return response, nil
	})}
	err := (&CrtshProvider{Client: client}).Enumerate(context.Background(), "example.com", make(chan string, 1))
	if err == nil || !strings.Contains(err.Error(), "decodificando resposta do crt.sh") {
		t.Fatalf("erro de JSON ausente ou pouco claro: %v", err)
	}
}
