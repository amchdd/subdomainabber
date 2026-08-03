package notify

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/amchdd/subdomainabber/internal/classification"
	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/finding"
	"github.com/amchdd/subdomainabber/internal/presentation"
	"github.com/amchdd/subdomainabber/internal/verify"
)

type DispatcherConfig struct {
	Workers         int
	DiscordWebhook  string
	TelegramConfig  string
	MinimumSeverity string
}

type Dispatcher struct {
	queue           chan AlertEvent
	wg              sync.WaitGroup
	notifiers       []Notifier
	minimumSeverity AlertSeverity

	queueMu sync.RWMutex
	closed  bool

	mu   sync.Mutex
	seen map[string]struct{}
}

func NewDispatcher(workers int) *Dispatcher {
	dispatcher, _ := NewDispatcherWithOptions(DispatcherConfig{Workers: workers})
	return dispatcher
}

// NewDispatcherWithConfig preserva a API pública do alpha. Novos chamadores
// devem usar NewDispatcherWithOptions para configurar o filtro de severidade.
func NewDispatcherWithConfig(workers int, discordWebhook, telegramConfig string) (*Dispatcher, error) {
	return NewDispatcherWithOptions(DispatcherConfig{
		Workers: workers, DiscordWebhook: discordWebhook, TelegramConfig: telegramConfig,
		MinimumSeverity: "medium",
	})
}

func NewDispatcherWithOptions(options DispatcherConfig) (*Dispatcher, error) {
	minimum, err := ParseSeverity(options.MinimumSeverity)
	if err != nil {
		return nil, err
	}

	var notifiers []Notifier
	discord := NewDiscordNotifier()
	if options.DiscordWebhook != "" {
		discord = newDiscordNotifier(options.DiscordWebhook)
	}
	if discord != nil {
		notifiers = append(notifiers, discord)
	}
	telegram := NewTelegramNotifier()
	if options.TelegramConfig != "" {
		telegram, err = newTelegramNotifierFromConfig(options.TelegramConfig)
		if err != nil {
			return nil, err
		}
	}
	if telegram != nil {
		notifiers = append(notifiers, telegram)
	}
	if options.Workers < 1 {
		options.Workers = 1
	}

	dispatcher := &Dispatcher{
		queue:           make(chan AlertEvent, 1000),
		notifiers:       notifiers,
		minimumSeverity: minimum,
		seen:            make(map[string]struct{}),
	}
	for index := 0; index < options.Workers; index++ {
		dispatcher.wg.Add(1)
		go dispatcher.worker()
	}
	return dispatcher, nil
}

// BeginBatch reinicia a deduplicação em memória para uma nova iteração da
// varredura. No lote, achados NS usam o corte de zona como chave para evitar
// alertas repetidos por hosts descendentes.
func (dispatcher *Dispatcher) BeginBatch() {
	if dispatcher == nil {
		return
	}
	dispatcher.mu.Lock()
	dispatcher.seen = make(map[string]struct{})
	dispatcher.mu.Unlock()
}

func (dispatcher *Dispatcher) Dispatch(result *verify.Result) {
	if dispatcher == nil || result == nil || result.NewAnalysis == nil || result.State == verify.Unchanged || result.State == verify.Incomplete {
		return
	}
	if isAlwaysSuppressedInitialResult(result.OldClassification, result.NewClassification) {
		return
	}

	severity := dispatcher.mapSeverity(result.OldClassification, result.NewClassification)
	if severity == "" || severityRank(severity) < severityRank(dispatcher.minimumSeverity) {
		return
	}

	vector, resource, evidence := alertContext(result.NewAnalysis)
	changedAt := result.NewAnalysis.LastStateChange
	if changedAt.IsZero() {
		changedAt = time.Now().UTC()
	}
	event := AlertEvent{
		Host:          result.Host,
		PreviousState: result.OldClassification,
		CurrentState:  result.NewClassification,
		StateChange:   result.State,
		Score:         result.NewAnalysis.RiskScore,
		Severity:      severity,
		ChangedAt:     changedAt,
		Evidences:     evidence,
		Vector:        vector,
		Resource:      resource,
	}

	identity := strings.ToLower(strings.Join([]string{
		string(result.State), vector, resource, result.OldClassification, result.NewClassification,
	}, "|"))
	dispatcher.mu.Lock()
	if _, duplicate := dispatcher.seen[identity]; duplicate {
		dispatcher.mu.Unlock()
		return
	}
	dispatcher.seen[identity] = struct{}{}
	dispatcher.mu.Unlock()

	if len(dispatcher.notifiers) == 0 {
		return
	}
	dispatcher.queueMu.RLock()
	defer dispatcher.queueMu.RUnlock()
	if dispatcher.closed || dispatcher.queue == nil {
		return
	}
	select {
	case dispatcher.queue <- event:
	default:
		log.Printf("[!] fila de notificações cheia; descartando alerta %s para %s", severity, resource)
	}
}

func (dispatcher *Dispatcher) DispatchAnalysis(analysis *core.HostAnalysis) {
	if analysis == nil {
		return
	}
	dispatcher.Dispatch(&verify.Result{
		Host:              analysis.Host,
		OldClassification: "",
		NewClassification: analysis.Classification,
		State:             verify.Discovered,
		NewAnalysis:       analysis,
	})
}

func (dispatcher *Dispatcher) Flush() {
	if dispatcher == nil {
		return
	}
	dispatcher.queueMu.Lock()
	if !dispatcher.closed {
		dispatcher.closed = true
		if dispatcher.queue != nil {
			close(dispatcher.queue)
		}
	}
	dispatcher.queueMu.Unlock()
	dispatcher.wg.Wait()
}

func (dispatcher *Dispatcher) worker() {
	defer dispatcher.wg.Done()
	for event := range dispatcher.queue {
		for _, notifier := range dispatcher.notifiers {
			timeoutContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := notifier.Send(timeoutContext, event); err != nil {
				log.Printf("[-] falha ao notificar sobre %s: %v", event.Resource, err)
			}
			cancel()
		}
	}
}

func ParseSeverity(value string) (AlertSeverity, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "medium", "warning":
		return SeverityMedium, nil
	case "info":
		return SeverityInfo, nil
	case "low":
		return SeverityLow, nil
	case "high":
		return SeverityHigh, nil
	case "critical":
		return SeverityCritical, nil
	default:
		return "", fmt.Errorf("severidade de notificação não suportada %q; use info, low, medium, high ou critical", value)
	}
}

func (dispatcher *Dispatcher) mapSeverity(oldClass, newClass string) AlertSeverity {
	if oldClass != "" && classification.RiskRank(newClass) < classification.RiskRank(oldClass) {
		return SeverityInfo
	}
	return classificationSeverity(newClass)
}

func classificationSeverity(level string) AlertSeverity {
	switch level {
	case classification.LevelTakenOver, classification.LevelZoneControlConfirmed:
		return SeverityCritical
	case classification.LevelConfirmed, classification.LevelDelegationClaimabilityVerified, classification.LevelTakeoverable:
		return SeverityHigh
	case classification.LevelLikelyTakeoverable, classification.LevelDelegationTakeoverCandidate, classification.LevelExposed:
		return SeverityMedium
	case classification.LevelOrphaned, classification.LevelDelegationBroken, classification.LevelMisconfigured:
		return SeverityLow
	case classification.LevelHealthy, classification.LevelUnknown, classification.LevelInsufficientEvidence, "":
		return SeverityInfo
	default:
		return SeverityInfo
	}
}

// ClassificationSeverity expõe o mesmo mapeamento estável de severidade usado
// nos filtros de notificação, evitando divergência entre a CLI humana e o Discord.
func ClassificationSeverity(level string) AlertSeverity {
	return classificationSeverity(level)
}

func severityRank(severity AlertSeverity) int {
	switch severity {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// SeverityRank retorna a posição monotônica de apresentação da severidade analisada.
func SeverityRank(severity AlertSeverity) int {
	return severityRank(severity)
}

func isAlwaysSuppressedInitialResult(oldClass, newClass string) bool {
	if oldClass != "" {
		return false
	}
	switch newClass {
	case classification.LevelHealthy, classification.LevelUnknown, classification.LevelInsufficientEvidence, "":
		return true
	default:
		return false
	}
}

func alertContext(analysis *core.HostAnalysis) (vector, resource, evidence string) {
	primary := finding.Primary(analysis)
	vector, resource = primary.Vector, primary.Resource
	selected := primary.Evidence
	if selected.Type != "" {
		evidence = selected.Type
		if description := presentation.EvidenceDescription(selected); description != "" {
			evidence += " — " + description
		}
	}
	if evidence == "" {
		evidence = "Resumo da evidência causal indisponível"
	}
	return vector, resource, evidence
}
