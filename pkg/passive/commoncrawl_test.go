package passive

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCommonCrawlExtractsHostsFromLatestIndex(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/collinfo.json" {
			_, _ = writer.Write([]byte(`[{"cdx-api":"` + server.URL + `/index"}]`))
			return
		}
		if request.URL.Query().Get("matchType") != "domain" || request.URL.Query().Get("fl") != "url" {
			t.Fatalf("consulta inesperada: %s", request.URL.RawQuery)
		}
		_, _ = writer.Write([]byte("{\"url\":\"https://api.example.com/v1\"}\n{\"url\":\"https://deep.dev.example.com/app.js\"}\n"))
	}))
	defer server.Close()

	provider := &CommonCrawlProvider{Client: server.Client(), IndexURL: server.URL + "/index"}
	out := make(chan string, 4)
	if err := provider.Enumerate(context.Background(), "example.com", out); err != nil {
		t.Fatal(err)
	}
	close(out)
	var names []string
	for name := range out {
		names = append(names, name)
	}
	if len(names) != 2 || names[0] != "api.example.com" || names[1] != "deep.dev.example.com" {
		t.Fatalf("hostnames inesperados: %v", names)
	}
}

func TestCommonCrawlRejectsMalformedLine(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("{"))
	}))
	defer server.Close()
	provider := &CommonCrawlProvider{Client: server.Client(), IndexURL: server.URL}
	if err := provider.Enumerate(context.Background(), "example.com", make(chan string, 1)); err == nil {
		t.Fatal("resposta inválida foi aceita")
	}
}
