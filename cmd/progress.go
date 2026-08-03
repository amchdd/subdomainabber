package cmd

import (
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amchdd/subdomainabber/internal/classification"
	"github.com/amchdd/subdomainabber/pkg/ratelimit"
)

const scanProgressInterval = 10 * time.Second

type domainOutcome int

const (
	domainCompleted domainOutcome = iota
	domainSkipped
	domainFailed
	domainCanceled
)

func (outcome domainOutcome) String() string {
	switch outcome {
	case domainCompleted:
		return "concluído"
	case domainSkipped:
		return "ignorado"
	case domainFailed:
		return "falhou"
	case domainCanceled:
		return "cancelado"
	default:
		return "desconhecido"
	}
}

type domainResult struct {
	Outcome        domainOutcome
	Classification string
	Actionable     bool
	FatalErr       error
}

type scanProgressSnapshot struct {
	Total           int64
	Started         int64
	Active          int64
	Completed       int64
	Skipped         int64
	Failed          int64
	Canceled        int64
	Processed       int64
	NotStarted      int64
	Actionable      int64
	Classifications map[string]int64
	Operations      ratelimit.StatsSnapshot
	Elapsed         time.Duration
}

type scanProgress struct {
	total            int64
	requestedWorkers int
	effectiveWorkers int
	limiter          *ratelimit.Limiter
	writer           io.Writer
	enabled          bool
	startedAt        time.Time
	started          atomic.Int64
	active           atomic.Int64
	completed        atomic.Int64
	skipped          atomic.Int64
	failed           atomic.Int64
	canceled         atomic.Int64
	actionable       atomic.Int64
	classificationMu sync.Mutex
	classifications  map[string]int64
	stop             chan struct{}
	done             chan struct{}
	startOnce        sync.Once
	stopOnce         sync.Once
	initialGranted   uint64
}

func newScanProgress(
	total int,
	requestedWorkers int,
	effectiveWorkers int,
	limiter *ratelimit.Limiter,
	writer io.Writer,
	enabled bool,
) *scanProgress {
	initialStats := ratelimit.StatsSnapshot{}
	if limiter != nil {
		initialStats = limiter.Stats()
	}
	return &scanProgress{
		total:            int64(total),
		requestedWorkers: requestedWorkers,
		effectiveWorkers: effectiveWorkers,
		limiter:          limiter,
		writer:           writer,
		enabled:          enabled,
		startedAt:        time.Now(),
		stop:             make(chan struct{}),
		done:             make(chan struct{}),
		classifications:  make(map[string]int64),
		initialGranted:   initialStats.Granted,
	}
}

func (progress *scanProgress) Start() {
	if progress == nil || !progress.enabled {
		return
	}
	progress.startOnce.Do(func() {
		fmt.Fprintln(progress.writer, progress.Format(progress.Snapshot()))
		go func() {
			defer close(progress.done)
			ticker := time.NewTicker(scanProgressInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					fmt.Fprintln(progress.writer, progress.Format(progress.Snapshot()))
				case <-progress.stop:
					return
				}
			}
		}()
	})
}

func (progress *scanProgress) Stop() {
	if progress == nil || !progress.enabled {
		return
	}
	progress.stopOnce.Do(func() { close(progress.stop) })
	<-progress.done
}

func (progress *scanProgress) HostStarted() {
	progress.started.Add(1)
	progress.active.Add(1)
}

func (progress *scanProgress) HostFinished(result domainResult) {
	progress.active.Add(-1)
	switch result.Outcome {
	case domainCompleted:
		progress.completed.Add(1)
	case domainSkipped:
		progress.skipped.Add(1)
	case domainFailed:
		progress.failed.Add(1)
	case domainCanceled:
		progress.canceled.Add(1)
	}
	if result.Actionable {
		progress.actionable.Add(1)
	}
	if result.Classification != "" {
		progress.classificationMu.Lock()
		progress.classifications[result.Classification]++
		progress.classificationMu.Unlock()
	}
}

func (progress *scanProgress) Snapshot() scanProgressSnapshot {
	started := progress.started.Load()
	completed := progress.completed.Load()
	skipped := progress.skipped.Load()
	failed := progress.failed.Load()
	canceled := progress.canceled.Load()
	processed := completed + skipped + failed
	notStarted := progress.total - started
	if notStarted < 0 {
		notStarted = 0
	}
	operations := ratelimit.StatsSnapshot{}
	if progress.limiter != nil {
		operations = progress.limiter.Stats()
	}
	if operations.Granted >= progress.initialGranted {
		operations.Granted -= progress.initialGranted
	}
	progress.classificationMu.Lock()
	classifications := make(map[string]int64, len(progress.classifications))
	for classification, count := range progress.classifications {
		classifications[classification] = count
	}
	progress.classificationMu.Unlock()
	return scanProgressSnapshot{
		Total:           progress.total,
		Started:         started,
		Active:          progress.active.Load(),
		Completed:       completed,
		Skipped:         skipped,
		Failed:          failed,
		Canceled:        canceled,
		Processed:       processed,
		NotStarted:      notStarted,
		Actionable:      progress.actionable.Load(),
		Classifications: classifications,
		Operations:      operations,
		Elapsed:         time.Since(progress.startedAt),
	}
}

func (progress *scanProgress) Format(snapshot scanProgressSnapshot) string {
	workerText := fmt.Sprintf("%d/%d", snapshot.Active, progress.effectiveWorkers)
	if progress.requestedWorkers != progress.effectiveWorkers {
		workerText += fmt.Sprintf(" (%d solicitados)", progress.requestedWorkers)
	}

	hostsPerSecond, eta, hasRate := progressRateAndETA(snapshot)
	rateText := ""
	if hasRate {
		rateText = fmt.Sprintf("%.2f hosts/s | tempo estimado: %s", hostsPerSecond, compactDuration(eta))
	}
	if snapshot.Processed == 0 {
		rateText = "aguardando as primeiras conclusões"
	} else if rateText == "" {
		rateText = fmt.Sprintf("calibrando a estimativa (%d/10 hosts)", snapshot.Processed)
	}
	return fmt.Sprintf(
		"[*] Progresso: %d/%d processados | achados: %d | processamentos ativos: %s | operações: %d liberadas, %d aguardando | decorrido: %s | %s",
		snapshot.Processed,
		snapshot.Total,
		snapshot.Actionable,
		workerText,
		snapshot.Operations.Granted,
		snapshot.Operations.Waiting,
		compactDuration(snapshot.Elapsed),
		rateText,
	)
}

func progressRateAndETA(snapshot scanProgressSnapshot) (float64, time.Duration, bool) {
	if snapshot.Processed < 10 || snapshot.Elapsed <= 0 {
		return 0, 0, false
	}
	hostsPerSecond := float64(snapshot.Processed) / snapshot.Elapsed.Seconds()
	remaining := snapshot.Total - snapshot.Processed - snapshot.Canceled
	if remaining < 0 {
		remaining = 0
	}
	eta := time.Duration(float64(remaining)/hostsPerSecond) * time.Second
	return hostsPerSecond, eta, true
}

func compactDuration(duration time.Duration) string {
	if duration < 0 {
		duration = 0
	}
	return duration.Round(time.Second).String()
}

func formatScanBreakdown(snapshot scanProgressSnapshot) string {
	var takeover, delegation, exposure, orphaned, misconfigured, healthy, inconclusive int64
	for level, count := range snapshot.Classifications {
		switch level {
		case classification.LevelTakenOver, classification.LevelConfirmed,
			classification.LevelTakeoverable, classification.LevelLikelyTakeoverable:
			takeover += count
		case classification.LevelZoneControlConfirmed, classification.LevelDelegationClaimabilityVerified,
			classification.LevelDelegationTakeoverCandidate, classification.LevelDelegationBroken:
			delegation += count
		case classification.LevelExposed:
			exposure += count
		case classification.LevelOrphaned:
			orphaned += count
		case classification.LevelMisconfigured:
			misconfigured += count
		case classification.LevelHealthy:
			healthy += count
		default:
			inconclusive += count
		}
	}
	return fmt.Sprintf(
		"[*] Resumo: %s decorridos | %d operações | %d hosts acionáveis | takeover: %d | delegação: %d | exposição: %d | órfãos: %d | configurações: %d | saudáveis: %d | inconclusivos: %d | ignorados: %d",
		compactDuration(snapshot.Elapsed), snapshot.Operations.Granted, snapshot.Actionable,
		takeover, delegation, exposure, orphaned, misconfigured, healthy, inconclusive, snapshot.Skipped,
	)
}

func writerIsTerminal(writer io.Writer) bool {
	file, ok := writer.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
