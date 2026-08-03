// Package claim implementa reivindicações de provedores explicitamente autorizadas e auditáveis.
package claim

import (
	"context"
	"errors"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
)

// ErrClaimNotMatched indica que um recurso do provedor foi criado e removido com
// segurança, mas sua identidade atribuída não correspondeu à referência pública pendente.
var ErrClaimNotMatched = errors.New("a reivindicação no provedor não correspondeu à referência órfã")

// ErrUnsafeClaimState indica que uma operação externa pode ter deixado um
// recurso pendente. O motor interrompe novas reivindicações até que a
// reconciliação confirme a limpeza.
var ErrUnsafeClaimState = errors.New("a execução agressiva foi interrompida por um estado de reivindicação inseguro")

type Status string

const (
	StatusUnsupported      Status = "UNSUPPORTED"
	StatusAttempting       Status = "ATTEMPTING"
	StatusClaimSucceeded   Status = "CLAIM_SUCCEEDED"
	StatusClaimFailed      Status = "CLAIM_FAILED"
	StatusReleasePending   Status = "RELEASE_PENDING"
	StatusReleaseSucceeded Status = "RELEASE_SUCCEEDED"
	StatusReleaseFailed    Status = "RELEASE_FAILED"
)

type Request struct {
	Host       string
	Candidate  core.ProviderCandidate
	ProofToken string
	Vector     string
	Resource   string
	Metadata   map[string]string
}

type Receipt struct {
	ProviderID string            `json:"provider_id"`
	ExternalID string            `json:"external_id"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	ClaimedAt  time.Time         `json:"claimed_at"`
}

type ControlProof struct {
	Controlled bool
	Details    string
}

type ReleaseReceipt struct {
	ReleasedAt time.Time
	Details    string
}

// ClaimFailure carrega um recibo quando um provedor criou um recurso, mas não
// conseguiu concluir a reivindicação ou sua reversão imediata. O motor o persiste antes
// de tentar a liberação novamente, para que a reconciliação continue possível.
type ClaimFailure struct {
	Receipt Receipt
	Err     error
}

func (failure *ClaimFailure) Error() string {
	if failure.Err == nil {
		return "a reivindicação parcial falhou"
	}
	return failure.Err.Error()
}

func (failure *ClaimFailure) Unwrap() error { return failure.Err }

type Provider interface {
	ProviderID() string
	Supports(core.ProviderCandidate) bool
	Claim(context.Context, Request) (Receipt, error)
	VerifyControl(context.Context, Receipt) (ControlProof, error)
	Release(context.Context, Receipt) (ReleaseReceipt, error)
}

// RecoverableProvider localiza uma reivindicação criada por esta ferramenta a
// partir do registro gravado antes da operação externa. A implementação só
// pode retornar found=true quando a identidade e o token de prova pertencem à
// tentativa registrada; recursos apenas semelhantes nunca devem ser removidos.
type RecoverableProvider interface {
	RecoverClaim(context.Context, Receipt) (recovered Receipt, found bool, err error)
}
