package evidence

import (
	"context"
	"fmt"

	"github.com/amchdd/subdomainabber/internal/core"
	"golang.org/x/sync/errgroup"
)

// Registry mantém e orquestra uma lista explícita de coletores.
type Registry struct {
	collectors []Collector
}

// NewRegistry cria um Registry com a ordem exata de coletores desejada.
func NewRegistry(collectors []Collector) *Registry {
	return &Registry{
		collectors: collectors,
	}
}

// BeginBatch redefine os caches locais dos coletores antes de uma nova iteração da varredura.
func (r *Registry) BeginBatch() {
	for _, collector := range r.collectors {
		if resetter, ok := collector.(BatchResetter); ok {
			resetter.BeginBatch()
		}
	}
}

// Run executa os coletores em fases, paralelizando somente os módulos independentes.
func (r *Registry) Run(ctx context.Context, analysis *core.HostAnalysis) error {
	analysis.InitMutex()
	if err := r.runSequentialPhase(ctx, analysis, PhaseProviderDiscovery); err != nil {
		return err
	}
	if err := r.runSequentialPhase(ctx, analysis, PhaseHTTPBaseline); err != nil {
		return err
	}
	if err := r.runIndependent(ctx, analysis); err != nil {
		return err
	}
	if err := r.runSequentialPhase(ctx, analysis, PhaseHTTPMutation); err != nil {
		return err
	}

	corr := NewCorrelator()
	if err := corr.Collect(ctx, analysis); err != nil {
		return err
	}
	return r.runSequentialPhase(ctx, analysis, PhaseImpact)
}

func (r *Registry) runSequentialPhase(ctx context.Context, analysis *core.HostAnalysis, phase CollectorPhase) error {
	for _, collector := range r.collectors {
		if phaseOf(collector) != phase {
			continue
		}
		if err := collector.Collect(ctx, analysis); err != nil {
			return fmt.Errorf("fase %d do coletor: %w", phase, err)
		}
	}
	return nil
}

func (r *Registry) runIndependent(ctx context.Context, analysis *core.HostAnalysis) error {
	var g errgroup.Group
	g.SetLimit(10)

	for _, c := range r.collectors {
		if phaseOf(c) != PhaseIndependent {
			continue
		}
		c := c // Captura a variável do laço.
		g.Go(func() error {
			if err := c.Collect(ctx, analysis); err != nil {
				return fmt.Errorf("coletor independente: %w", err)
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}

	return nil
}
