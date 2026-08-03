package evidence

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
)

type independentFailureAfterStart struct{ started <-chan struct{} }

func (collector independentFailureAfterStart) Collect(context.Context, *core.HostAnalysis) error {
	<-collector.started
	return errors.New("falha simulada")
}

type independentCancellationObserver struct {
	started  chan<- struct{}
	canceled *atomic.Bool
}

func (collector independentCancellationObserver) Collect(ctx context.Context, _ *core.HostAnalysis) error {
	close(collector.started)
	timer := time.NewTimer(20 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		collector.canceled.Store(true)
	case <-timer.C:
	}
	return nil
}

func TestIndependentCollectorFailureDoesNotCancelSiblingEvidence(t *testing.T) {
	started := make(chan struct{})
	var canceled atomic.Bool
	registry := NewRegistry([]Collector{
		independentCancellationObserver{started: started, canceled: &canceled},
		independentFailureAfterStart{started: started},
	})

	err := registry.Run(context.Background(), &core.HostAnalysis{Host: "example.test"})
	if err == nil {
		t.Fatal("a falha do coletor independente foi ocultada")
	}
	if canceled.Load() {
		t.Fatal("a falha de um coletor cancelou outro módulo independente")
	}
}
