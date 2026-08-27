package platform

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHackerOneLoadsProgramsAndPaginatedScopes(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		user, token, ok := request.BasicAuth()
		if !ok || user != "pesquisador" || token != "segredo" {
			t.Errorf("autenticação básica ausente")
		}
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.URL.Path == "/v1/hackers/programs":
			_, _ = response.Write([]byte(`{"data":[{"id":9,"type":"program","attributes":{"handle":"acme","name":"Acme","submission_state":"open","state":"public_mode","offers_bounties":true}}],"links":{}}`))
		case request.URL.Path == "/v1/hackers/programs/acme/structured_scopes" && request.URL.Query().Get("page[number]") == "1":
			_, _ = response.Write([]byte(`{"data":[{"id":"10","type":"structured-scope","attributes":{"asset_type":"WILDCARD","asset_identifier":"*.example.com","eligible_for_bounty":true,"eligible_for_submission":true,"instruction":"Sem força bruta","max_severity":"critical"}}],"links":{"next":"` + server.URL + `/v1/hackers/programs/acme/structured_scopes?page[number]=2&page[size]=100"}}`))
		case request.URL.Path == "/v1/hackers/programs/acme/structured_scopes" && request.URL.Query().Get("page[number]") == "2":
			_, _ = response.Write([]byte(`{"data":[{"id":"11","type":"structured-scope","attributes":{"asset_type":"URL","asset_identifier":"https://api.example.com","eligible_for_bounty":false,"eligible_for_submission":true}}],"links":{}}`))
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	client := NewHackerOne(server.Client(), server.URL, "pesquisador", "segredo")
	programs, err := client.Programs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(programs) != 1 || len(programs[0].Assets) != 2 {
		t.Fatalf("programas incompletos: %+v", programs)
	}
	if programs[0].ID != "9" || programs[0].Assets[0].ReconRoot != "example.com" {
		t.Fatalf("normalização incompleta: %+v", programs[0])
	}
	if !strings.Contains(programs[0].Assets[0].Instruction, "força bruta") {
		t.Fatalf("instrução perdida: %+v", programs[0].Assets[0])
	}
}
