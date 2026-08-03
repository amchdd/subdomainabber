package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/amchdd/subdomainabber/pkg/ratelimit"
)

func TestEffectiveHostConcurrencyTracksRateLimit(t *testing.T) {
	if got := effectiveHostConcurrency(50, 10); got != 10 {
		t.Fatalf("expected 10 effective workers, got %d", got)
	}
	if got := effectiveHostConcurrency(5, 10); got != 5 {
		t.Fatalf("expected requested worker count, got %d", got)
	}
	if got := effectiveHostConcurrency(50, 0); got != 50 {
		t.Fatalf("disabled limiter changed workers: %d", got)
	}
}

func TestProgressFormatPortugueseBeforeAndAfterCompletion(t *testing.T) {
	progress := newScanProgress(124, 50, 10, ratelimit.New(10), &bytes.Buffer{}, true)
	before := progress.Format(scanProgressSnapshot{Total: 124, Active: 10})
	for _, expected := range []string{"Progresso", "0/124", "10/10", "50 solicitados", "primeiras conclusões"} {
		if !strings.Contains(before, expected) {
			t.Fatalf("Portuguese progress missing %q: %s", expected, before)
		}
	}

	after := progress.Format(scanProgressSnapshot{
		Total: 124, Active: 10, Processed: 20, Elapsed: 20 * time.Second,
		Operations: ratelimit.StatsSnapshot{Granted: 400, Waiting: 30},
	})
	for _, expected := range []string{"20/124", "400", "30", "1.00 hosts/s", "tempo estimado"} {
		if !strings.Contains(after, expected) {
			t.Fatalf("Portuguese progress missing %q: %s", expected, after)
		}
	}
}

func TestProgressPrintsInitialStateImmediately(t *testing.T) {
	var output bytes.Buffer
	progress := newScanProgress(3, 2, 2, ratelimit.New(10), &output, true)
	progress.Start()
	progress.Stop()
	if text := output.String(); !strings.Contains(text, "Progresso: 0/3 processados") {
		t.Fatalf("o estado inicial do progresso não foi exibido: %q", text)
	}
}

func TestProgressSnapshotTracksCancellationAndNotStarted(t *testing.T) {
	progress := newScanProgress(5, 2, 2, ratelimit.New(10), &bytes.Buffer{}, false)
	progress.HostStarted()
	progress.HostStarted()
	progress.HostFinished(domainResult{Outcome: domainCompleted, Classification: "HEALTHY"})
	progress.HostFinished(domainResult{Outcome: domainCanceled})
	snapshot := progress.Snapshot()
	if snapshot.Completed != 1 || snapshot.Canceled != 1 || snapshot.NotStarted != 3 || snapshot.Processed != 1 {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
}

func TestProgressWarmsUpETABeforeTenHosts(t *testing.T) {
	progress := newScanProgress(100, 10, 10, ratelimit.New(10), &bytes.Buffer{}, true)
	snapshot := scanProgressSnapshot{Total: 100, Processed: 3, Elapsed: 30 * time.Second}
	if _, _, ok := progressRateAndETA(snapshot); ok {
		t.Fatal("ETA was exposed before the warm-up threshold")
	}
	if output := progress.Format(snapshot); !strings.Contains(output, "calibrando a estimativa (3/10 hosts)") {
		t.Fatalf("missing warm-up message: %s", output)
	}
}

func TestScanBreakdownIsLocalizedAndActionOriented(t *testing.T) {
	snapshot := scanProgressSnapshot{
		Processed: 5, Actionable: 2, Skipped: 1, Elapsed: time.Minute,
		Classifications: map[string]int64{
			"LIKELY_TAKEOVERABLE": 1,
			"MISCONFIGURED":       1,
			"HEALTHY":             1,
			"UNKNOWN":             1,
		},
		Operations: ratelimit.StatsSnapshot{Granted: 123},
	}
	output := formatScanBreakdown(snapshot)
	for _, expected := range []string{"123 operações", "2 hosts acionáveis", "takeover: 1", "configurações: 1", "saudáveis: 1", "inconclusivos: 1"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("summary missing %q: %s", expected, output)
		}
	}
}

func TestContextCancellationIsRecognizedThroughWrapping(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !isContextCancellation(ctx, fmt.Errorf("collector: %w", context.Canceled)) {
		t.Fatal("wrapped cancellation was not recognized")
	}
	if isContextCancellation(context.Background(), errors.New("network failed")) {
		t.Fatal("ordinary network failure was treated as cancellation")
	}
}
