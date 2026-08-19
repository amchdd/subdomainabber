package learning

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
	_ "modernc.org/sqlite"
)

func TestDiscoverUsesPublicSuffixAndResponseSignals(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE hosts (host TEXT, classification TEXT, dns_records TEXT, evidences TEXT)`); err != nil {
		t.Fatal(err)
	}
	dnsJSON, _ := json.Marshal(core.DNSRecordSet{CNAME: []string{"missing.vendor.co.uk"}})
	evidences, _ := json.Marshal([]core.Evidence{{Type: "HTTP_RESPONSE", Metadata: map[string]string{
		"status": "404", "body_hash": "abc", "server": "edge",
	}}})
	for _, host := range []string{"a.example", "b.example"} {
		if _, err := db.Exec(`INSERT INTO hosts VALUES (?, 'ORPHANED', ?, ?)`, host, string(dnsJSON), string(evidences)); err != nil {
			t.Fatal(err)
		}
	}
	candidates, err := NewEngine(db).Discover(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].TargetCNAME != "vendor.co.uk" || candidates[0].BodyHash != "abc" {
		t.Fatalf("candidato inesperado: %+v", candidates)
	}
}
