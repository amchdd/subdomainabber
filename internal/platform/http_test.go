package platform

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIClientRetriesRateLimit(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		attempts++
		response.Header().Set("Content-Type", "application/json")
		if attempts == 1 {
			response.Header().Set("Retry-After", "0")
			http.Error(response, "limite", http.StatusTooManyRequests)
			return
		}
		_, _ = response.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	var output struct {
		OK bool `json:"ok"`
	}
	client := newAPIClient(server.Client(), server.URL, nil)
	if err := client.get(context.Background(), "/programs", &output); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || !output.OK {
		t.Fatalf("retomada inesperada: tentativas=%d saída=%+v", attempts, output)
	}
}

func TestAPIClientRejectsCrossOriginPagination(t *testing.T) {
	client := newAPIClient(http.DefaultClient, "https://api.example.com", nil)
	var output any
	err := client.get(context.Background(), "https://evil.example/programs", &output)
	if err == nil {
		t.Fatal("paginação externa foi aceita")
	}
}

func TestAPIClientPreservesBasePath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/external/researcher/v1/programs" {
			t.Fatalf("prefixo da API perdido: %s", request.URL.Path)
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	client := newAPIClient(server.Client(), server.URL+"/external/researcher", nil)
	var output any
	if err := client.get(context.Background(), "/v1/programs", &output); err != nil {
		t.Fatal(err)
	}
}

func TestVisitPageRejectsCycle(t *testing.T) {
	seen := make(map[string]struct{})
	if err := visitPage(seen, "/programs?page=1"); err != nil {
		t.Fatal(err)
	}
	if err := visitPage(seen, "/programs?page=1"); err == nil {
		t.Fatal("ciclo de paginação foi aceito")
	}
}

func TestAPIPacerOnlyAppliesToOfficialOrigin(t *testing.T) {
	if apiPacer("https://api.hackerone.com", "api.hackerone.com", 50) == nil {
		t.Fatal("limite oficial da HackerOne não foi aplicado")
	}
	if apiPacer("http://127.0.0.1:8080", "api.hackerone.com", 50) != nil {
		t.Fatal("cliente de teste recebeu limite da origem oficial")
	}
}
