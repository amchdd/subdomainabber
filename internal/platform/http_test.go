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
