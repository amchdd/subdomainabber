package evidence

import (
	"context"

	"github.com/amchdd/subdomainabber/internal/core"
)

type HTTPPostureCollector struct{}

func NewHTTPPostureCollector() *HTTPPostureCollector { return &HTTPPostureCollector{} }

func (*HTTPPostureCollector) Phase() CollectorPhase { return PhaseImpact }

func (*HTTPPostureCollector) Collect(_ context.Context, analysis *core.HostAnalysis) error {
	if analysis == nil {
		return nil
	}
	analysis.AddTestedVector("HTTP_POSTURE")
	return nil
}
