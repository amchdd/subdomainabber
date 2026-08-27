package platform

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHackerOneLoadsProgramsAndPaginatedScopes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		user, token, ok := request.BasicAuth()
		if !ok || user != "pesquisador" || token != "segredo" {
			t.Errorf("autenticação básica ausente")
		}
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.URL.Path == "/v1/hackers/programs":
			_, _ = response.Write([]byte(`{"data":[{"id":9,"type":"program","attributes":{"handle":"acme","name":"Acme","submission_state":"open","state":"public_mode","offers_bounties":true}}],"links":{}}`))
		case request.URL.Path == "/v1/hackers/programs/acme/structured_scopes" && request.URL.Query().Get("filter[id__gt]") == "0":
			_, _ = response.Write([]byte(`{"data":[{"id":"10","type":"structured-scope","attributes":{"asset_type":"WILDCARD","asset_identifier":"*.example.com","eligible_for_bounty":true,"eligible_for_submission":true,"instruction":"Sem força bruta","max_severity":"critical"}},{"id":"11","type":"structured-scope","attributes":{"asset_type":"URL","asset_identifier":"https://api.example.com","eligible_for_bounty":false,"eligible_for_submission":true}}],"links":{}}`))
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

func TestHackerOneScopesUseCursorBeyondFirstHundred(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		cursor := request.URL.Query().Get("filter[id__gt]")
		start, count := 1, 100
		if cursor == "100" {
			start, count = 101, 1
		} else if cursor != "0" {
			http.Error(response, "cursor inesperado", http.StatusBadRequest)
			return
		}
		var payload strings.Builder
		payload.WriteString(`{"data":[`)
		for index := 0; index < count; index++ {
			if index > 0 {
				payload.WriteByte(',')
			}
			id := start + index
			fmt.Fprintf(&payload, `{"id":%d,"attributes":{"asset_type":"DOMAIN","asset_identifier":"host%d.example.com","eligible_for_submission":true}}`, id, id)
		}
		payload.WriteString(`]}`)
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(payload.String()))
	}))
	defer server.Close()

	client := NewHackerOne(server.Client(), server.URL, "pesquisador", "segredo")
	assets, err := client.scopes(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 101 || requests != 2 || assets[100].ID != "101" {
		t.Fatalf("paginação por cursor incompleta: ativos=%d requisições=%d", len(assets), requests)
	}
}
