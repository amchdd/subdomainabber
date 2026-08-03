package claim

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amchdd/subdomainabber/internal/classification"
	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/storage"
)

type AuditStore interface {
	CreateClaimAudit(context.Context, storage.ClaimAuditRecord) (int64, error)
	UpdateClaimAudit(context.Context, int64, string, string, string, string) error
	PendingClaimAudits(context.Context) ([]storage.ClaimAuditRecord, error)
}

type Engine struct {
	store       AuditStore
	providers   map[string]Provider
	allowlist   map[string]struct{}
	attemptMu   sync.Mutex
	attempted   map[string]struct{}
	operationMu sync.Mutex
	stateMu     sync.RWMutex
	haltedErr   error
}

func NewEngine(store AuditStore, allowlist []string, providers ...Provider) (*Engine, error) {
	if store == nil {
		return nil, fmt.Errorf("o armazenamento da auditoria de reivindicação é obrigatório")
	}
	engine := &Engine{
		store: store, providers: make(map[string]Provider), allowlist: make(map[string]struct{}),
		attempted: make(map[string]struct{}),
	}
	for _, host := range allowlist {
		normalized := normalizeHost(host)
		if normalized != "" {
			engine.allowlist[normalized] = struct{}{}
		}
	}
	if len(engine.allowlist) == 0 {
		return nil, fmt.Errorf("a reivindicação automática exige uma lista permitida explícita de hosts não vazia")
	}
	for _, provider := range providers {
		if provider != nil && provider.ProviderID() != "" {
			engine.providers[provider.ProviderID()] = provider
		}
	}
	if len(engine.providers) == 0 {
		return nil, fmt.Errorf("a reivindicação automática exige ao menos uma implementação real de provedor")
	}
	return engine, nil
}

func (engine *Engine) Execute(ctx context.Context, analysis *core.HostAnalysis) error {
	if analysis == nil || !claimEligibleAnalysis(analysis) {
		return nil
	}
	host := normalizeHost(analysis.Host)
	if _, allowed := engine.allowlist[host]; !allowed {
		return nil
	}

	// Operações que criam recursos são deliberadamente serializadas. Se uma
	// limpeza falhar, nenhuma outra goroutine pode iniciar uma nova criação antes
	// de o estado inseguro ser registrado e observado.
	engine.operationMu.Lock()
	defer engine.operationMu.Unlock()
	if unsafeErr := engine.unsafeState(); unsafeErr != nil {
		analysis.AddEvidence(core.Evidence{
			Type: "CLAIM_ENGINE_HALTED", Source: "CLAIM_ENGINE",
			Description: unsafeErr.Error(), Weight: 0, Confidence: 100,
		})
		return unsafeErr
	}

	provider, candidate := engine.providerFor(analysis)
	if provider == nil {
		auditID, err := engine.store.CreateClaimAudit(ctx, storage.ClaimAuditRecord{
			Host: host, ProviderID: "unsupported", Status: string(StatusUnsupported),
			LastError: "nenhum provedor com reivindicação real oferece suporte ao candidato vinculado ao provedor",
		})
		if err == nil {
			analysis.AddEvidence(core.Evidence{Type: "CLAIM_UNSUPPORTED", Source: "CLAIM_ENGINE", Description: "Nenhum provedor com reivindicação real oferece suporte ao candidato vinculado ao provedor.", Weight: 0, Confidence: 100, Metadata: map[string]string{"audit_id": strconv.FormatInt(auditID, 10)}})
		}
		return err
	}

	vector := strings.ToUpper(strings.TrimSpace(candidate.Vector))
	if vector == "" {
		vector = "CNAME"
	}
	resource := candidate.Resource
	if resource == "" {
		resource = candidate.CNAME
	}
	attemptKey := strings.ToLower(provider.ProviderID() + "|" + vector + "|" + normalizeHost(resource))
	if !engine.beginAttempt(attemptKey) {
		analysis.AddEvidence(core.Evidence{
			Type: "CLAIM_DUPLICATE_RESOURCE_SKIPPED", Source: provider.ProviderID(),
			Description: "O mesmo recurso do provedor já foi testado durante este lote da varredura.",
			Confidence:  100, IsNegative: true,
			Metadata: map[string]string{"vector": vector, "resource": resource},
		})
		return nil
	}

	token, err := randomProofToken()
	if err != nil {
		return err
	}
	request := Request{
		Host: host, Candidate: candidate, ProofToken: token,
		Vector: vector, Resource: resource, Metadata: candidate.Metadata,
	}
	provisional := provisionalReceipt(provider.ProviderID(), request)
	provisionalJSON, err := json.Marshal(provisional)
	if err != nil {
		return fmt.Errorf("codificando o registro preventivo da reivindicação: %w", err)
	}
	auditID, err := engine.store.CreateClaimAudit(ctx, storage.ClaimAuditRecord{
		Host: host, ProviderID: provider.ProviderID(), Status: string(StatusAttempting),
		ReceiptJSON: string(provisionalJSON),
	})
	if err != nil {
		return fmt.Errorf("criando o registro preventivo da reivindicação: %w", err)
	}

	receipt, err := provider.Claim(ctx, request)
	if err != nil {
		var auditErr error
		var partial *ClaimFailure
		if errors.As(err, &partial) {
			if partial.Receipt.ExternalID == "" {
				// O registro preventivo permanece em ATTEMPTING para que o provedor
				// possa localizar o recurso pelo token na próxima reconciliação.
				unsafeErr := engine.haltUnsafe(fmt.Errorf("%s pode ter criado um recurso sem devolver identidade recuperável: %w", provider.ProviderID(), err))
				analysis.AddEvidence(core.Evidence{
					Type: "CLAIM_RECOVERY_REQUIRED", Source: provider.ProviderID(),
					Description: unsafeErr.Error(), Weight: 0, Confidence: 100,
					Metadata: map[string]string{"audit_id": strconv.FormatInt(auditID, 10)},
				})
				return unsafeErr
			}

			auditErr = engine.update(auditID, StatusReleasePending, partial.Receipt, err)
			_, releaseErr := engine.releaseWithTimeout(provider, partial.Receipt)
			if releaseErr != nil {
				statusErr := engine.update(auditID, StatusReleaseFailed, partial.Receipt, releaseErr)
				analysis.AddEvidence(core.Evidence{
					Type: "CLAIM_RELEASE_FAILED", Source: provider.ProviderID(),
					Description: releaseErr.Error(), Confidence: 100,
					Metadata: map[string]string{"audit_id": strconv.FormatInt(auditID, 10), "external_id": partial.Receipt.ExternalID},
				})
				unsafeErr := engine.haltUnsafe(fmt.Errorf("a reivindicação parcial de %s falhou e a liberação também falhou: %w", provider.ProviderID(), releaseErr))
				return errors.Join(unsafeErr, auditErr, statusErr)
			}
			auditErr = errors.Join(auditErr, engine.update(auditID, StatusReleaseSucceeded, partial.Receipt, err))
			analysis.AddEvidence(core.Evidence{
				Type: "CLAIM_RELEASE_SUCCEEDED", Source: provider.ProviderID(),
				Description: "A reivindicação parcial no provedor foi revertida.", Confidence: 100,
				Metadata: map[string]string{"audit_id": strconv.FormatInt(auditID, 10), "external_id": partial.Receipt.ExternalID},
			})
		} else {
			auditErr = engine.update(auditID, StatusClaimFailed, Receipt{}, err)
		}
		if errors.Is(err, ErrClaimNotMatched) {
			markClaimNotDemonstrated(analysis, vector, resource, provider.ProviderID(), auditID, err)
		}
		analysis.AddEvidence(core.Evidence{Type: "CLAIM_FAILED", Source: provider.ProviderID(), Description: err.Error(), Weight: 0, Confidence: 100, Metadata: map[string]string{"audit_id": strconv.FormatInt(auditID, 10)}})
		return errors.Join(fmt.Errorf("a reivindicação de %s falhou: %w", provider.ProviderID(), err), auditErr)
	}
	if receipt.ProviderID != provider.ProviderID() || receipt.ExternalID == "" {
		invalidReceipt := fmt.Errorf("o provedor retornou um recibo de reivindicação inválido")
		persistErr := engine.update(auditID, StatusAttempting, provisional, invalidReceipt)
		if receipt.ExternalID != "" {
			_, releaseErr := engine.releaseWithTimeout(provider, receipt)
			if releaseErr != nil {
				statusErr := engine.update(auditID, StatusReleaseFailed, receipt, releaseErr)
				unsafeErr := engine.haltUnsafe(fmt.Errorf("a limpeza do recibo inválido falhou: %w", releaseErr))
				return errors.Join(invalidReceipt, persistErr, unsafeErr, statusErr)
			}
			statusErr := engine.update(auditID, StatusReleaseSucceeded, receipt, invalidReceipt)
			return errors.Join(invalidReceipt, persistErr, statusErr)
		}
		unsafeErr := engine.haltUnsafe(fmt.Errorf("%w; a criação externa não pode ser descartada sem uma identidade de recurso", invalidReceipt))
		return errors.Join(unsafeErr, persistErr)
	}
	if err := engine.update(auditID, StatusClaimSucceeded, receipt, nil); err != nil {
		persistErr := fmt.Errorf("persistindo o recibo da reivindicação bem-sucedida: %w", err)
		_, releaseErr := engine.releaseWithTimeout(provider, receipt)
		if releaseErr != nil {
			statusErr := engine.update(auditID, StatusReleaseFailed, receipt, releaseErr)
			unsafeErr := engine.haltUnsafe(fmt.Errorf("a reversão de emergência também falhou: %w", releaseErr))
			return errors.Join(persistErr, unsafeErr, statusErr)
		}
		statusErr := engine.update(auditID, StatusReleaseSucceeded, receipt, persistErr)
		return errors.Join(persistErr, statusErr)
	}

	proof, controlErr := provider.VerifyControl(ctx, receipt)
	if controlErr == nil && !proof.Controlled {
		controlErr = fmt.Errorf("a reivindicação no provedor não produziu uma prova positiva de controle")
	}
	if controlErr == nil {
		evidenceType := controlEvidenceType(vector)
		analysis.AddEvidence(core.Evidence{
			Type:        evidenceType,
			Source:      provider.ProviderID(),
			Description: "Recurso reivindicado e controle verificado em ambiente explicitamente autorizado.",
			Weight:      100,
			Confidence:  100,
			Metadata: map[string]string{
				"audit_id":    strconv.FormatInt(auditID, 10),
				"external_id": receipt.ExternalID,
				"provider_id": receipt.ProviderID,
				"proof":       proof.Details,
				"vector":      vector,
				"resource":    resource,
			},
		})
		if evidenceType != "CLAIM_SUCCESS" {
			analysis.AddEvidence(core.Evidence{
				Type: "CLAIM_SUCCESS", Source: provider.ProviderID(),
				Description: "O controle ativo do vetor foi comprovado por um fluxo autorizado de criação, verificação e liberação.",
				Weight:      100, Confidence: 100,
				Metadata: map[string]string{"vector": vector, "resource": resource, "proof": proof.Details},
			})
		}
		analysis.VerificationScore = 100
		analysis.ActiveVerification = &core.VerificationResult{
			Provider: provider.ProviderID(), Vector: vector, Resource: resource,
			Verified: true, ControlProven: true, Confidence: 100, Evidence: proof.Details,
		}
		markVectorControlConfirmed(analysis, vector, resource)
	}
	if controlErr != nil {
		analysis.AddEvidence(core.Evidence{Type: "CLAIM_CONTROL_FAILED", Source: provider.ProviderID(), Description: controlErr.Error(), Weight: 0, Confidence: 100, Metadata: map[string]string{"audit_id": strconv.FormatInt(auditID, 10), "external_id": receipt.ExternalID}})
	}

	pendingErr := engine.update(auditID, StatusReleasePending, receipt, controlErr)
	releaseCtx, cancelRelease := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelRelease()
	release, releaseErr := provider.Release(releaseCtx, receipt)
	if releaseErr != nil {
		statusErr := engine.update(auditID, StatusReleaseFailed, receipt, releaseErr)
		analysis.AddEvidence(core.Evidence{Type: "CLAIM_RELEASE_FAILED", Source: provider.ProviderID(), Description: releaseErr.Error(), Weight: 0, Confidence: 100, Metadata: map[string]string{"audit_id": strconv.FormatInt(auditID, 10), "external_id": receipt.ExternalID}})
		unsafeErr := engine.haltUnsafe(fmt.Errorf("a liberação de %s falhou: %w", receipt.ExternalID, releaseErr))
		return errors.Join(unsafeErr, statusErr)
	}
	if err := engine.update(auditID, StatusReleaseSucceeded, receipt, controlErr); err != nil {
		return fmt.Errorf("persistindo o sucesso da liberação: %w", err)
	}
	if pendingErr != nil {
		analysis.AddEvidence(core.Evidence{Type: "CLAIM_AUDIT_WARNING", Source: provider.ProviderID(), Description: "O estado RELEASE_PENDING não pôde ser persistido antes da liberação, mas a liberação final foi confirmada.", Weight: 0, Confidence: 100, Metadata: map[string]string{"audit_id": strconv.FormatInt(auditID, 10)}})
	}
	analysis.AddEvidence(core.Evidence{Type: "CLAIM_RELEASE_SUCCEEDED", Source: provider.ProviderID(), Description: release.Details, Weight: 0, Confidence: 100, Metadata: map[string]string{"audit_id": strconv.FormatInt(auditID, 10), "external_id": receipt.ExternalID}})
	if controlErr != nil {
		return fmt.Errorf("a verificação de controle falhou após a reivindicação: %w", controlErr)
	}
	return nil
}

func (engine *Engine) beginAttempt(key string) bool {
	engine.attemptMu.Lock()
	defer engine.attemptMu.Unlock()
	if _, exists := engine.attempted[key]; exists {
		return false
	}
	engine.attempted[key] = struct{}{}
	return true
}

func markClaimNotDemonstrated(analysis *core.HostAnalysis, vector, resource, providerID string, auditID int64, claimErr error) {
	evidenceType := "CLAIMABILITY_NOT_DEMONSTRATED"
	if strings.EqualFold(vector, "NS") {
		evidenceType = "DELEGATION_CLAIMABILITY_NOT_DEMONSTRATED"
		if analysis.Delegation != nil {
			analysis.Delegation.Claimability = core.ClaimabilityNotVerified
		}
	}
	analysis.AddEvidence(core.Evidence{
		Type: evidenceType, Source: providerID,
		Description: claimErr.Error(), Confidence: 100, IsNegative: true,
		Metadata: map[string]string{
			"audit_id": strconv.FormatInt(auditID, 10), "vector": vector, "resource": resource,
		},
	})
}

func (engine *Engine) releaseWithTimeout(provider Provider, receipt Receipt) (ReleaseReceipt, error) {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return provider.Release(cleanupCtx, receipt)
}

func (engine *Engine) haltUnsafe(cause error) error {
	if cause == nil {
		cause = errors.New("causa não informada")
	}
	engine.stateMu.Lock()
	defer engine.stateMu.Unlock()
	if engine.haltedErr == nil {
		engine.haltedErr = fmt.Errorf("%w: %v", ErrUnsafeClaimState, cause)
	}
	return engine.haltedErr
}

func (engine *Engine) unsafeState() error {
	engine.stateMu.RLock()
	defer engine.stateMu.RUnlock()
	return engine.haltedErr
}

func (engine *Engine) clearUnsafe() {
	engine.stateMu.Lock()
	engine.haltedErr = nil
	engine.stateMu.Unlock()
}

func (engine *Engine) Reconcile(ctx context.Context) error {
	engine.operationMu.Lock()
	defer engine.operationMu.Unlock()

	records, err := engine.store.PendingClaimAudits(ctx)
	if err != nil {
		return engine.haltUnsafe(fmt.Errorf("consultando a auditoria pendente: %w", err))
	}
	var failures []string
	for _, record := range records {
		provider := engine.providers[record.ProviderID]
		if provider == nil {
			failures = append(failures, fmt.Sprintf("auditoria %d: provedor não suportado %s", record.ID, record.ProviderID))
			continue
		}
		var receipt Receipt
		if err := json.Unmarshal([]byte(record.ReceiptJSON), &receipt); err != nil {
			failures = append(failures, fmt.Sprintf("auditoria %d: recibo inválido", record.ID))
			continue
		}
		if record.Status == string(StatusAttempting) {
			recoverer, ok := provider.(RecoverableProvider)
			if !ok {
				failures = append(failures, fmt.Sprintf("auditoria %d: o provedor não oferece reconciliação de tentativas interrompidas", record.ID))
				continue
			}
			recovered, found, recoverErr := recoverer.RecoverClaim(ctx, receipt)
			if recoverErr != nil {
				failures = append(failures, fmt.Sprintf("auditoria %d: recuperando reivindicação interrompida: %v", record.ID, recoverErr))
				continue
			}
			if !found {
				if err := engine.update(record.ID, StatusClaimFailed, Receipt{}, fmt.Errorf("nenhum recurso criado por esta tentativa foi localizado")); err != nil {
					failures = append(failures, fmt.Sprintf("auditoria %d: %v", record.ID, err))
				}
				continue
			}
			receipt = recovered
			if err := engine.update(record.ID, StatusClaimSucceeded, receipt, nil); err != nil {
				failures = append(failures, fmt.Sprintf("auditoria %d: persistindo recibo recuperado: %v", record.ID, err))
				continue
			}
		}
		if receipt.ExternalID == "" {
			failures = append(failures, fmt.Sprintf("auditoria %d: recibo sem identificador externo", record.ID))
			continue
		}
		if err := engine.update(record.ID, StatusReleasePending, receipt, nil); err != nil {
			failures = append(failures, fmt.Sprintf("auditoria %d: %v", record.ID, err))
			continue
		}
		if _, err := provider.Release(ctx, receipt); err != nil {
			_ = engine.update(record.ID, StatusReleaseFailed, receipt, err)
			failures = append(failures, fmt.Sprintf("auditoria %d: %v", record.ID, err))
			continue
		}
		if err := engine.update(record.ID, StatusReleaseSucceeded, receipt, nil); err != nil {
			failures = append(failures, fmt.Sprintf("auditoria %d: %v", record.ID, err))
		}
	}
	if len(failures) > 0 {
		return engine.haltUnsafe(fmt.Errorf("falhas na reconciliação de reivindicações: %s", strings.Join(failures, "; ")))
	}
	engine.clearUnsafe()
	return nil
}

func (engine *Engine) providerFor(analysis *core.HostAnalysis) (Provider, core.ProviderCandidate) {
	for _, candidate := range analysis.ProviderCandidateSnapshot() {
		if !claimEligibleCandidate(analysis, candidate) {
			continue
		}
		for _, provider := range engine.providers {
			if provider.Supports(candidate) {
				return provider, candidate
			}
		}
	}
	return nil, core.ProviderCandidate{}
}

func (engine *Engine) update(id int64, status Status, receipt Receipt, operationErr error) error {
	receiptJSON := ""
	if receipt.ExternalID != "" {
		encoded, err := json.Marshal(receipt)
		if err != nil {
			return err
		}
		receiptJSON = string(encoded)
	}
	lastError := ""
	if operationErr != nil {
		lastError = operationErr.Error()
	}
	updateCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return engine.store.UpdateClaimAudit(updateCtx, id, string(status), receipt.ExternalID, receiptJSON, lastError)
}

func claimEligibleAnalysis(analysis *core.HostAnalysis) bool {
	if analysis == nil || len(analysis.ProviderCandidateSnapshot()) == 0 {
		return false
	}
	for _, candidate := range analysis.ProviderCandidateSnapshot() {
		if claimEligibleCandidate(analysis, candidate) {
			return true
		}
	}
	return false
}

func claimEligibleCandidate(analysis *core.HostAnalysis, candidate core.ProviderCandidate) bool {
	vector := strings.ToUpper(strings.TrimSpace(candidate.Vector))
	if vector == "" {
		vector = "CNAME"
	}

	// Uma correspondência com um provedor de DNS gerenciado é comum e não autoriza
	// a criação de uma zona hospedada. O Route 53 só é elegível quando a ferramenta
	// comprova o candidato completo publicado pela zona pai e suas precondições de DNSSEC.
	if vector == "NS" {
		return hasAnalysisEvidence(analysis, "DELEGATION_TAKEOVER_CANDIDATE") ||
			hasAnalysisEvidence(analysis, "DELEGATION_CLAIMABILITY_VERIFIED")
	}

	switch analysis.Classification {
	case classification.LevelLikelyTakeoverable, classification.LevelTakeoverable, classification.LevelOrphaned:
		return true
	default:
		return false
	}
}

func hasAnalysisEvidence(analysis *core.HostAnalysis, evidenceType string) bool {
	for _, evidence := range analysis.Evidences {
		if evidence.Type == evidenceType {
			return true
		}
	}
	return false
}

func controlEvidenceType(vector string) string {
	switch strings.ToUpper(vector) {
	case "NS":
		return "ZONE_CONTROL_CONFIRMED"
	case "MX":
		return "MX_DELIVERY_CONTROL_VERIFIED"
	case "SRV":
		return "SRV_SERVICE_CONTROL_VERIFIED"
	case "SPF":
		return "SPF_AUTHORIZATION_CONTROL_VERIFIED"
	case "TXT":
		return "TXT_BINDING_CONTROL_VERIFIED"
	case "A", "AAAA":
		return "CLOUD_IP_CONTROL_VERIFIED"
	default:
		return "CLAIM_SUCCESS"
	}
}

func markVectorControlConfirmed(analysis *core.HostAnalysis, vector, resource string) {
	switch strings.ToUpper(vector) {
	case "NS":
		if analysis.Delegation != nil {
			analysis.Delegation.Claimability = core.ClaimabilityControlConfirmed
		}
	case "MX":
		for index := range analysis.MXCandidates {
			if analysis.MXCandidates[index].Target == resource {
				analysis.MXCandidates[index].Claimability = core.ClaimabilityControlConfirmed
			}
		}
	case "SRV":
		for index := range analysis.SRVCandidates {
			if analysis.SRVCandidates[index].Record.Target == resource {
				analysis.SRVCandidates[index].Claimability = core.ClaimabilityControlConfirmed
			}
		}
	case "SPF":
		for index := range analysis.SPFCandidates {
			if analysis.SPFCandidates[index].Domain == resource {
				analysis.SPFCandidates[index].Claimability = core.ClaimabilityControlConfirmed
			}
		}
	case "TXT":
		for index := range analysis.TXTCandidates {
			analysis.TXTCandidates[index].Claimability = core.ClaimabilityControlConfirmed
			analysis.TXTCandidates[index].State = "CONTROL_CONFIRMED"
		}
	case "A", "AAAA":
		for index := range analysis.CloudIPCandidates {
			if analysis.CloudIPCandidates[index].IP == resource {
				analysis.CloudIPCandidates[index].Claimability = core.ClaimabilityControlConfirmed
			}
		}
	}
}

func normalizeHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

func provisionalReceipt(providerID string, request Request) Receipt {
	metadata := make(map[string]string, len(request.Metadata)+4)
	for key, value := range request.Metadata {
		metadata[key] = value
	}
	metadata["request_host"] = normalizeHost(request.Host)
	metadata["request_resource"] = normalizeHost(request.Resource)
	metadata["request_vector"] = strings.ToUpper(strings.TrimSpace(request.Vector))
	metadata["proof_token"] = request.ProofToken
	return Receipt{
		ProviderID: providerID,
		Metadata:   metadata,
		ClaimedAt:  time.Now().UTC(),
	}
}

func randomProofToken() (string, error) {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return "", fmt.Errorf("gerando token de prova da reivindicação: %w", err)
	}
	return hex.EncodeToString(data), nil
}
