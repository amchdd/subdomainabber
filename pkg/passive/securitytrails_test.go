package passive

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityTrailsSendsTokenAndExpandsLabels(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("APIKEY") != "segredo" {
			t.Fatalf("token ausente")
		}
		_, _ = writer.Write([]byte(`{"subdomains":["api","deep.dev","full.example.com"]}`))
	}))
	defer server.Close()
	provider := &SecurityTrailsProvider{Client: server.Client(), Token: "segredo", BaseURL: server.URL}
	out := make(chan string, 4)
	if err := provider.Enumerate(context.Background(), "example.com", out); err != nil {
		t.Fatal(err)
	}
	close(out)
	var names []string
	for name := range out {
		names = append(names, name)
	}
	if len(names) != 3 || names[0] != "api.example.com" || names[1] != "deep.dev.example.com" || names[2] != "full.example.com" {
		t.Fatalf("nomes inesperados: %v", names)
	}
}
