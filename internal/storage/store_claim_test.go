package storage

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
)

func TestClaimAuditPersistsOnlyRecoverableReceiptsAsPending(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "claim-audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	withoutReceiptID, err := store.CreateClaimAudit(ctx, ClaimAuditRecord{
		Host: "unallocated.example.com", ProviderID: "aws_s3", Status: "ATTEMPTING",
	})
	if err != nil {
		t.Fatal(err)
	}
	provisionalID, err := store.CreateClaimAudit(ctx, ClaimAuditRecord{
		Host: "pending.example.com", ProviderID: "aws_s3", Status: "ATTEMPTING",
		ReceiptJSON: `{"provider_id":"aws_s3","metadata":{"request_host":"pending.example.com","proof_token":"token"}}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	withReceiptID, err := store.CreateClaimAudit(ctx, ClaimAuditRecord{
		Host: "bucket.example.com", ProviderID: "aws_s3", Status: "CLAIM_SUCCEEDED",
		ExternalID: "bucket.example.com", ReceiptJSON: `{"provider_id":"aws_s3","external_id":"bucket.example.com"}`,
	})
	if err != nil {
		t.Fatal(err)
	}

	pending, err := store.PendingClaimAudits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 2 || pending[0].ID != provisionalID || pending[1].ID != withReceiptID {
		t.Fatalf("pending audits = %#v", pending)
	}

	if err := store.UpdateClaimAudit(ctx, provisionalID, "CLAIM_FAILED", "", "", "nenhum recurso localizado"); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateClaimAudit(ctx, withReceiptID, "RELEASE_SUCCEEDED", "bucket.example.com", pending[1].ReceiptJSON, ""); err != nil {
		t.Fatal(err)
	}
	pending, err = store.PendingClaimAudits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("released audit remained pending: %#v", pending)
	}

	var status string
	if err := store.db.QueryRowContext(ctx, "SELECT status FROM claim_audits WHERE id = ?", withoutReceiptID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "ATTEMPTING" {
		t.Fatalf("non-recoverable audit was altered: %q", status)
	}
}

func TestSaveAnalysisPersistsRevalidationProfile(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "profile.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	analysis := &core.HostAnalysis{
		Host:           "profile.example.com",
		Classification: "UNKNOWN",
		TestedVectors:  []string{"DNS", "HTTP", "TLS"},
		ScanProfile: &core.ScanProfile{
			Version: 1, SignatureDigest: "sha256:test", CheckNS: true, SRVOwners: []string{"_sip._tcp"},
		},
	}
	if err := store.SaveAnalysis(analysis); err != nil {
		t.Fatal(err)
	}
	hosts, err := store.GetAllHosts(context.Background(), QueryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || !reflect.DeepEqual(hosts[0].TestedVectors, analysis.TestedVectors) || !reflect.DeepEqual(hosts[0].ScanProfile, analysis.ScanProfile) {
		t.Fatalf("perfil persistido incorretamente: %#v", hosts)
	}
}

func TestSaveAnalysisRollsBackHostWhenRelatedPersistenceFails(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "transaction.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.db.Exec(`INSERT INTO unknown_providers (root_domain, example_hosts) VALUES ('provider.example', '{')`); err != nil {
		t.Fatal(err)
	}
	analysis := &core.HostAnalysis{
		Host:           "candidate.example.com",
		Classification: "UNKNOWN",
		UnknownProvider: &core.UnknownProviderEvidence{
			RootDomain: "provider.example",
		},
	}
	err = store.SaveAnalysis(analysis)
	if err == nil || !strings.Contains(err.Error(), "decodificando hosts de exemplo") {
		t.Fatalf("falha relacionada não foi propagada: %v", err)
	}
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM hosts WHERE host = ?`, analysis.Host).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("host foi persistido apesar do rollback da transação")
	}
}

func TestSaveAnalysisUpdatesExistingHostAndPreservesTimeline(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "timeline.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	analysis := &core.HostAnalysis{Host: "repeat.example.com", Classification: "UNKNOWN"}
	if err := store.SaveAnalysis(analysis); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`
		UPDATE hosts
		SET first_seen = '2020-01-01 00:00:00', last_seen = '2020-01-01 00:00:00', last_state_change = '2020-01-01 00:00:00'
		WHERE host = ?`, analysis.Host); err != nil {
		t.Fatal(err)
	}

	if err := store.SaveAnalysis(analysis); err != nil {
		t.Fatal(err)
	}
	var firstSeen, lastSeen, stateChange time.Time
	var previous string
	if err := store.db.QueryRow(`SELECT first_seen, last_seen, last_state_change, previous_classification FROM hosts WHERE host = ?`, analysis.Host).
		Scan(&firstSeen, &lastSeen, &stateChange, &previous); err != nil {
		t.Fatal(err)
	}
	old := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if !firstSeen.Equal(old) || !stateChange.Equal(old) || !lastSeen.After(old) || previous != "" {
		t.Fatalf("same-state timeline = first:%s last:%s change:%s previous:%q", firstSeen, lastSeen, stateChange, previous)
	}

	analysis.Classification = "LIKELY_TAKEOVERABLE"
	if err := store.SaveAnalysis(analysis); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT first_seen, last_state_change, previous_classification FROM hosts WHERE host = ?`, analysis.Host).
		Scan(&firstSeen, &stateChange, &previous); err != nil {
		t.Fatal(err)
	}
	if !firstSeen.Equal(old) || !stateChange.After(old) || previous != "UNKNOWN" {
		t.Fatalf("changed-state timeline = first:%s change:%s previous:%q", firstSeen, stateChange, previous)
	}
}
