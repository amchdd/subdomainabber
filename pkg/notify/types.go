package notify

import (
	"context"
	"time"

	"github.com/amchdd/subdomainabber/internal/verify"
)

// AlertSeverity representa a gravidade do alerta.
type AlertSeverity string

const (
	SeverityInfo     AlertSeverity = "INFO"
	SeverityLow      AlertSeverity = "LOW"
	SeverityMedium   AlertSeverity = "MEDIUM"
	SeverityHigh     AlertSeverity = "HIGH"
	SeverityCritical AlertSeverity = "CRITICAL"
	SeverityWarning                = SeverityMedium
)

// AlertEvent é o pacote de dados enviado aos processadores de notificação.
type AlertEvent struct {
	Host          string
	PreviousState string
	CurrentState  string
	StateChange   verify.StateChange
	Score         int
	Severity      AlertSeverity
	ChangedAt     time.Time
	Evidences     string
	Vector        string
	Resource      string
}

// Notifier define o contrato genérico para adaptadores de notificação.
type Notifier interface {
	Send(ctx context.Context, event AlertEvent) error
}
