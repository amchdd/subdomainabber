package evidence

import (
	"context"
	"github.com/amchdd/subdomainabber/internal/core"
)

// Collector define o contrato dos coletores de evidências.
// Cada coletor recebe uma análise com o perfil DNS preenchido e acrescenta apenas
// as observações que lhe cabem. A classificação permanece a cargo do classificador.
type Collector interface {
	Collect(ctx context.Context, analysis *core.HostAnalysis) error
}

// BatchResetter é implementado por coletores cujos caches devem ficar restritos
// a uma única iteração de varredura, incluindo as iterações do modo daemon.
type BatchResetter interface {
	BeginBatch()
}

type CollectorPhase int

const (
	PhaseProviderDiscovery CollectorPhase = iota
	PhaseHTTPBaseline
	PhaseIndependent
	PhaseHTTPMutation
	PhaseImpact
)

type PhasedCollector interface {
	Collector
	Phase() CollectorPhase
}

func phaseOf(collector Collector) CollectorPhase {
	if phased, ok := collector.(PhasedCollector); ok {
		return phased.Phase()
	}
	return PhaseIndependent
}
