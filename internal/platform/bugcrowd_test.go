package platform

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBugcrowdCorrelatesProgramsGroupsAndTargets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Token usuario:segredo" {
			t.Errorf("token ausente")
		}
		if request.Header.Get("Accept") != "application/vnd.bugcrowd+json" {
			t.Errorf("accept incorreto")
		}
		response.Header().Set("Content-Type", "application/vnd.bugcrowd+json")
		switch request.URL.Path {
		case "/programs":
			_, _ = response.Write([]byte(`{"data":[{"type":"program","id":"p1","attributes":{"name":"Acme","code":"acme"},"relationships":{"current_brief":{"data":{"type":"program_brief","id":"b1"}}}}],"included":[{"type":"program_brief","id":"b1","relationships":{"target_groups":{"data":[{"type":"target_group","id":"g1"}]}}},{"type":"target_group","id":"g1","attributes":{"name":"Escopo principal","in_scope":true},"relationships":{"targets":{"data":[{"type":"target","id":"t1"}],"links":{"related":{"href":"/targets?filter[target_group_id]=g1","meta":{"count":1,"total_hits":1}}}}}},{"type":"target","id":"t1","attributes":{"name":"*.example.com","category":"website"}}],"links":{}}`))
		case "/targets":
			_, _ = response.Write([]byte(`{"data":[{"type":"target","id":"t1","attributes":{"name":"*.example.com","category":"website"}}],"links":{}}`))
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	client := NewBugcrowd(server.Client(), server.URL, "usuario:segredo")
	programs, err := client.Programs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(programs) != 1 || len(programs[0].Assets) != 1 {
		t.Fatalf("escopo incompleto: %+v", programs)
	}
	asset := programs[0].Assets[0]
	if asset.ID != "t1" || asset.Group != "Escopo principal" || !asset.Eligible || asset.ReconRoot != "example.com" {
		t.Fatalf("alvo incorreto: %+v", asset)
	}
}
