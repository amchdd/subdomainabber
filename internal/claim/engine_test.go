package claim

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/amchdd/subdomainabber/internal/classification"
	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/storage"
)

type memoryAuditStore struct {
	records   []storage.ClaimAuditRecord
	updateErr error
}

func (store *memoryAuditStore) CreateClaimAudit(_ context.Context, record storage.ClaimAuditRecord) (int64, error) {
	record.ID = int64(len(store.records) + 1)
	store.records = append(store.records, record)
	return record.ID, nil
}

func (store *memoryAuditStore) UpdateClaimAudit(_ context.Context, id int64, status, externalID, receiptJSON, lastError string) error {
	if store.updateErr != nil {
		return store.updateErr
	}
	for index := range store.records {
		if store.records[index].ID == id {
			store.records[index].Status = status
			store.records[index].ExternalID = externalID
			store.records[index].ReceiptJSON = receiptJSON
			store.records[index].LastError = lastError
			return nil
		}
	}
	return errors.New("audit not found")
}

func (store *memoryAuditStore) PendingClaimAudits(context.Context) ([]storage.ClaimAuditRecord, error) {
	var records []storage.ClaimAuditRecord
	for _, record := range store.records {
		if record.ReceiptJSON != "" && (record.Status == string(StatusAttempting) || record.Status == string(StatusClaimSucceeded) || record.Status == string(StatusReleasePending) || record.Status == string(StatusReleaseFailed)) {
			records = append(records, record)
		}
	}
	return records, nil
}

type fakeProvider struct {
	claimErr, proofErr, releaseErr error
	controlled                     bool
	claimCalls, proofCalls         int
	releaseCalls                   int
	recoverCalls                   int
	lastReceipt                    Receipt
}

func (*fakeProvider) ProviderID() string { return awsS3ProviderID }
func (*fakeProvider) Supports(candidate core.ProviderCandidate) bool {
	return candidate.ProviderID == awsS3ProviderID
}
func (provider *fakeProvider) Claim(_ context.Context, request Request) (Receipt, error) {
	provider.claimCalls++
	if provider.claimErr != nil {
		return Receipt{}, provider.claimErr
	}
	provider.lastReceipt = Receipt{ProviderID: provider.ProviderID(), ExternalID: request.Host, ClaimedAt: time.Now(), Metadata: map[string]string{"proof_key": "proof"}}
	return provider.lastReceipt, nil
}
func (provider *fakeProvider) VerifyControl(context.Context, Receipt) (ControlProof, error) {
	provider.proofCalls++
	return ControlProof{Controlled: provider.controlled, Details: "fake proof"}, provider.proofErr
}
func (provider *fakeProvider) Release(context.Context, Receipt) (ReleaseReceipt, error) {
	provider.releaseCalls++
	return ReleaseReceipt{Details: "fake release"}, provider.releaseErr
}

func (provider *fakeProvider) RecoverClaim(context.Context, Receipt) (Receipt, bool, error) {
	provider.recoverCalls++
	if provider.lastReceipt.ExternalID == "" {
		return Receipt{}, false, nil
	}
	return provider.lastReceipt, true, nil
}

func claimableAnalysis() *core.HostAnalysis {
	analysis := &core.HostAnalysis{Host: "bucket.example.com", Classification: classification.LevelLikelyTakeoverable}
	analysis.AddProviderCandidate(core.ProviderCandidate{ProviderID: awsS3ProviderID, Service: "AWS/S3", CNAME: "bucket.s3.amazonaws.com"})
	return analysis
}

func TestClaimEnginePersistsProofAndRealRelease(t *testing.T) {
	store := &memoryAuditStore{}
	provider := &fakeProvider{controlled: true}
	engine, err := NewEngine(store, []string{"bucket.example.com"}, provider)
	if err != nil {
		t.Fatal(err)
	}
	analysis := claimableAnalysis()
	if err := engine.Execute(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if provider.claimCalls != 1 || provider.proofCalls != 1 || provider.releaseCalls != 1 {
		t.Fatalf("provider calls = claim:%d proof:%d release:%d", provider.claimCalls, provider.proofCalls, provider.releaseCalls)
	}
	if len(store.records) != 1 || store.records[0].Status != string(StatusReleaseSucceeded) || store.records[0].ReceiptJSON == "" {
		t.Fatalf("audit = %#v", store.records)
	}
	if !hasEvidence(analysis, "CLAIM_SUCCESS") || !hasEvidence(analysis, "CLAIM_RELEASE_SUCCEEDED") {
		t.Fatalf("claim evidence = %#v", analysis.Evidences)
	}
}

func TestClaimFailureNeverCreatesReleasePending(t *testing.T) {
	store := &memoryAuditStore{}
	provider := &fakeProvider{claimErr: errors.New("create failed")}
	engine, _ := NewEngine(store, []string{"bucket.example.com"}, provider)
	analysis := claimableAnalysis()
	if err := engine.Execute(context.Background(), analysis); err == nil {
		t.Fatal("claim failure was hidden")
	}
	if provider.releaseCalls != 0 || store.records[0].Status != string(StatusClaimFailed) || store.records[0].ReceiptJSON != "" || !hasEvidence(analysis, "CLAIM_FAILED") {
		t.Fatalf("failed claim audit/provider = %#v / %#v", store.records[0], provider)
	}
}

func TestReleaseFailureRemainsPendingForReconciliation(t *testing.T) {
	store := &memoryAuditStore{}
	provider := &fakeProvider{controlled: true, releaseErr: errors.New("delete failed")}
	engine, _ := NewEngine(store, []string{"bucket.example.com", "other.example.com"}, provider)
	analysis := claimableAnalysis()
	if err := engine.Execute(context.Background(), analysis); err == nil || !errors.Is(err, ErrUnsafeClaimState) {
		t.Fatal("release failure was hidden")
	}
	if store.records[0].Status != string(StatusReleaseFailed) || !hasEvidence(analysis, "CLAIM_RELEASE_FAILED") {
		t.Fatalf("release failure audit/evidence = %#v / %#v", store.records[0], analysis.Evidences)
	}
	second := claimableAnalysis()
	second.Host = "other.example.com"
	second.ProviderCandidates[0].Resource = "other-bucket.s3.amazonaws.com"
	if err := engine.Execute(context.Background(), second); err == nil || !errors.Is(err, ErrUnsafeClaimState) {
		t.Fatalf("halted engine accepted another claim: %v", err)
	}
	if provider.claimCalls != 1 || !hasEvidence(second, "CLAIM_ENGINE_HALTED") {
		t.Fatalf("another resource was created after unsafe cleanup: calls=%d evidence=%#v", provider.claimCalls, second.Evidences)
	}
	provider.releaseErr = nil
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.records[0].Status != string(StatusReleaseSucceeded) || provider.releaseCalls != 2 {
		t.Fatalf("reconciled audit/provider = %#v / %#v", store.records[0], provider)
	}
}

func TestClaimFailureWithoutExternalIDHaltsUntilRecovery(t *testing.T) {
	store := &memoryAuditStore{}
	provider := &fakeProvider{claimErr: &ClaimFailure{Err: errors.New("provider omitted resource identity")}}
	engine, err := NewEngine(store, []string{"bucket.example.com"}, provider)
	if err != nil {
		t.Fatal(err)
	}
	analysis := claimableAnalysis()
	err = engine.Execute(context.Background(), analysis)
	if !errors.Is(err, ErrUnsafeClaimState) {
		t.Fatalf("unknown external state was not fatal: %v", err)
	}
	if len(store.records) != 1 || store.records[0].Status != string(StatusAttempting) || store.records[0].ReceiptJSON == "" {
		t.Fatalf("preventive journal was not preserved: %#v", store.records)
	}
	if !hasEvidence(analysis, "CLAIM_RECOVERY_REQUIRED") {
		t.Fatalf("missing recovery evidence: %#v", analysis.Evidences)
	}
}

func TestClaimNotMatchedUsesVectorSpecificEvidence(t *testing.T) {
	store := &memoryAuditStore{}
	provider := &fakeProvider{claimErr: ErrClaimNotMatched}
	engine, _ := NewEngine(store, []string{"bucket.example.com"}, provider)
	analysis := claimableAnalysis()
	if err := engine.Execute(context.Background(), analysis); err == nil {
		t.Fatal("claim mismatch was hidden")
	}
	if !hasEvidence(analysis, "CLAIMABILITY_NOT_DEMONSTRATED") || hasEvidence(analysis, "DELEGATION_CLAIMABILITY_NOT_DEMONSTRATED") {
		t.Fatalf("CNAME mismatch received delegation evidence: %#v", analysis.Evidences)
	}
}

func TestClaimEngineRejectsInconclusiveCNAMECandidate(t *testing.T) {
	store := &memoryAuditStore{}
	provider := &fakeProvider{controlled: true}
	engine, _ := NewEngine(store, []string{"bucket.example.com"}, provider)
	analysis := claimableAnalysis()
	analysis.Classification = classification.LevelUnknown
	if err := engine.Execute(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if provider.claimCalls != 0 || len(store.records) != 0 {
		t.Fatalf("inconclusive CNAME reached active claim: calls=%d audits=%#v", provider.claimCalls, store.records)
	}
}

func TestClaimReceiptPersistenceFailureKeepsRecoverableJournal(t *testing.T) {
	store := &memoryAuditStore{updateErr: errors.New("banco temporariamente indisponível")}
	provider := &fakeProvider{controlled: true, releaseErr: errors.New("falha temporária na exclusão")}
	engine, err := NewEngine(store, []string{"bucket.example.com"}, provider)
	if err != nil {
		t.Fatal(err)
	}
	analysis := claimableAnalysis()
	if err := engine.Execute(context.Background(), analysis); err == nil {
		t.Fatal("as falhas de persistência e reversão foram ocultadas")
	}
	if len(store.records) != 1 || store.records[0].Status != string(StatusAttempting) || store.records[0].ReceiptJSON == "" {
		t.Fatalf("o registro preventivo não permaneceu recuperável: %#v", store.records)
	}
	var provisional Receipt
	if err := json.Unmarshal([]byte(store.records[0].ReceiptJSON), &provisional); err != nil || provisional.Metadata["proof_token"] == "" {
		t.Fatalf("registro preventivo inválido: recibo=%#v erro=%v", provisional, err)
	}

	store.updateErr = nil
	provider.releaseErr = nil
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatalf("a reconciliação do registro preventivo falhou: %v", err)
	}
	if provider.recoverCalls != 1 || store.records[0].Status != string(StatusReleaseSucceeded) {
		t.Fatalf("reconciliação incompleta: recuperações=%d auditoria=%#v", provider.recoverCalls, store.records[0])
	}
}

func TestClaimEngineSkipsHostsOutsideExplicitAllowlist(t *testing.T) {
	store := &memoryAuditStore{}
	provider := &fakeProvider{controlled: true}
	engine, _ := NewEngine(store, []string{"other.example.com"}, provider)
	if err := engine.Execute(context.Background(), claimableAnalysis()); err != nil {
		t.Fatal(err)
	}
	if provider.claimCalls != 0 || len(store.records) != 0 {
		t.Fatalf("out-of-allowlist claim executed: calls=%d audits=%d", provider.claimCalls, len(store.records))
	}
}

func TestClaimEngineRejectsNSProviderContextWithoutDelegationCandidate(t *testing.T) {
	store := &memoryAuditStore{}
	provider := &fakeProvider{controlled: true}
	engine, _ := NewEngine(store, []string{"dev.example.com"}, provider)
	analysis := &core.HostAnalysis{
		Host: "dev.example.com", Classification: classification.LevelUnknown,
		Evidences: []core.Evidence{{Type: "NS_PROVIDER_MATCH"}},
	}
	analysis.AddProviderCandidate(core.ProviderCandidate{
		ProviderID: awsS3ProviderID, Service: "AWS Route53", Vector: "NS", Resource: "dev.example.com",
	})
	if err := engine.Execute(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if provider.claimCalls != 0 || len(store.records) != 0 {
		t.Fatalf("context-only NS candidate reached claim provider: calls=%d audits=%d", provider.claimCalls, len(store.records))
	}
}

func TestClaimEngineAttemptsSharedProviderResourceOnlyOncePerRun(t *testing.T) {
	store := &memoryAuditStore{}
	provider := &fakeProvider{controlled: true}
	engine, err := NewEngine(store, []string{"one.example.com", "two.example.com"}, provider)
	if err != nil {
		t.Fatal(err)
	}
	first := &core.HostAnalysis{Host: "one.example.com", Classification: classification.LevelLikelyTakeoverable}
	first.AddProviderCandidate(core.ProviderCandidate{
		ProviderID: awsS3ProviderID, Service: "AWS/S3", Vector: "CNAME",
		Resource: "shared-bucket.s3.amazonaws.com",
	})
	second := &core.HostAnalysis{Host: "two.example.com", Classification: classification.LevelLikelyTakeoverable}
	second.AddProviderCandidate(core.ProviderCandidate{
		ProviderID: awsS3ProviderID, Service: "AWS/S3", Vector: "CNAME",
		Resource: "shared-bucket.s3.amazonaws.com",
	})
	if err := engine.Execute(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := engine.Execute(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if provider.claimCalls != 1 || !hasEvidence(second, "CLAIM_DUPLICATE_RESOURCE_SKIPPED") {
		t.Fatalf("duplicate resource was claimed again: calls=%d evidence=%#v", provider.claimCalls, second.Evidences)
	}
}

func TestUnsupportedProviderIsExplicitAndNeverClaims(t *testing.T) {
	store := &memoryAuditStore{}
	provider := &fakeProvider{controlled: true}
	engine, _ := NewEngine(store, []string{"bucket.example.com"}, provider)
	analysis := &core.HostAnalysis{Host: "bucket.example.com", Classification: classification.LevelLikelyTakeoverable}
	analysis.AddProviderCandidate(core.ProviderCandidate{ProviderID: "github_pages", Service: "GitHub Pages", CNAME: "user.github.io"})
	if err := engine.Execute(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if provider.claimCalls != 0 || len(store.records) != 1 || store.records[0].Status != string(StatusUnsupported) || !hasEvidence(analysis, "CLAIM_UNSUPPORTED") {
		t.Fatalf("unsupported result = calls:%d audits:%#v evidence:%#v", provider.claimCalls, store.records, analysis.Evidences)
	}
}

func TestReconcilerProcessesOnlyReceiptsFromRealClaims(t *testing.T) {
	receipt, _ := json.Marshal(Receipt{ProviderID: awsS3ProviderID, ExternalID: "bucket.example.com", Metadata: map[string]string{"proof_key": "proof"}})
	store := &memoryAuditStore{records: []storage.ClaimAuditRecord{
		{ID: 1, Host: "no-receipt.example.com", ProviderID: awsS3ProviderID, Status: string(StatusAttempting)},
		{ID: 2, Host: "bucket.example.com", ProviderID: awsS3ProviderID, Status: string(StatusReleasePending), ReceiptJSON: string(receipt)},
	}}
	provider := &fakeProvider{}
	engine, _ := NewEngine(store, []string{"bucket.example.com"}, provider)
	if err := engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if provider.releaseCalls != 1 || store.records[0].Status != string(StatusAttempting) || store.records[1].Status != string(StatusReleaseSucceeded) {
		t.Fatalf("reconciliation touched wrong records: %#v", store.records)
	}
}

func hasEvidence(analysis *core.HostAnalysis, evidenceType string) bool {
	for _, evidence := range analysis.Evidences {
		if evidence.Type == evidenceType {
			return true
		}
	}
	return false
}
