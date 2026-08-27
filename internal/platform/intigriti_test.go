package platform

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIntigritiLoadsEveryAccessibleProgram(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer segredo" {
			t.Errorf("bearer ausente")
		}
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/programs":
			_, _ = response.Write([]byte(`{"maxCount":1,"records":[{"id":"p1","handle":"acme","name":"Acme","following":true,"status":{"id":1,"value":"Open"},"type":{"id":2,"value":"Bug bounty"},"webLinks":{"detail":"https://app.intigriti.com/programs/acme"}}]}`))
		case "/v1/programs/p1":
			_, _ = response.Write([]byte(`{"id":"p1","handle":"acme","name":"Acme","following":true,"status":{"id":1,"value":"Open"},"type":{"id":2,"value":"Bug bounty"},"domains":{"id":"v1","createdAt":1,"content":[{"id":"a1","type":{"id":1,"value":"Web application"},"endpoint":"*.example.com","tier":{"id":1,"value":"Tier 1"},"description":"Principal","requiredSkills":[]}]},"rulesOfEngagement":{"id":"r1","createdAt":1,"content":{"description":"Regras","testingRequirements":{"intigritiMe":false,"automatedTooling":20,"userAgent":"Researcher","requestHeader":"X-Research: yes"},"safeHarbour":true},"attachments":[]},"webLinks":{"detail":"https://app.intigriti.com/programs/acme"},"industry":"Tech"}`))
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	client := NewIntigriti(server.Client(), server.URL, "segredo")
	programs, err := client.Programs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(programs) != 1 || len(programs[0].Assets) != 1 {
		t.Fatalf("programa incompleto: %+v", programs)
	}
	if programs[0].Rules.AutomatedTooling != 20 || programs[0].Rules.UserAgent != "Researcher" {
		t.Fatalf("regras de automação perdidas: %+v", programs[0].Rules)
	}
}
