package classification

import (
	"strings"

	"github.com/amchdd/subdomainabber/internal/core"
)

func updateDecision(analysis *core.HostAnalysis, level string) {
	if analysis == nil {
		return
	}
	state := stateForLevel(level)
	selected := inferenceForState(analysis.Inferences, state)
	if state == core.ResultInconclusive && selected != nil {
		state = selected.State
		if state == core.ResultHealthy {
			state = core.ResultObservation
		}
	}
	if state == core.ResultObservation && selected != nil && selected.State == core.ResultSuppressed {
		state = core.ResultSuppressed
	}

	decision := core.Decision{State: state}
	if selected != nil {
		decision.Rule = selected.Rule
		decision.ReasonCodes = append([]string(nil), selected.ReasonCodes...)
		decision.ObservationConfidence = selected.ObservationConfidence
		decision.ClassificationConfidence = selected.ClassificationConfidence
		decision.ImpactConfidence = selected.ImpactConfidence
	}
	if len(decision.ReasonCodes) == 0 {
		decision.ReasonCodes = evidenceReasons(analysis)
	}
	if decision.Rule == "" {
		decision.Rule = inconclusiveReason(analysis, level)
	}
	if decision.ObservationConfidence == 0 {
		decision.ObservationConfidence = evidenceConfidence(analysis)
	}
	if analysis.ConfidenceScore > 0 {
		decision.ClassificationConfidence = analysis.ConfidenceScore
	}
	if decision.ClassificationConfidence == 0 {
		decision.ClassificationConfidence = evidenceConfidence(analysis)
	}
	if state == core.ResultConfirmed {
		decision.ImpactConfirmed = true
		if analysis.ActiveVerification != nil && analysis.ActiveVerification.ControlProven {
			decision.ClassificationConfidence = analysis.ActiveVerification.Confidence
		}
		if decision.ImpactConfidence == 0 {
			decision.ImpactConfidence = 100
		}
	}
	analysis.ResultState = state
	analysis.Decision = &decision
}

func stateForLevel(level string) core.ResultState {
	switch level {
	case LevelTakenOver, LevelConfirmed, LevelZoneControlConfirmed, LevelDelegationClaimabilityVerified, LevelExposed:
		return core.ResultConfirmed
	case LevelTakeoverable, LevelLikelyTakeoverable, LevelDelegationTakeoverCandidate, LevelDelegationBroken, LevelOrphaned, LevelMisconfigured:
		return core.ResultCandidate
	case LevelHealthy:
		return core.ResultHealthy
	case LevelUnknown:
		return core.ResultInconclusive
	default:
		return core.ResultInconclusive
	}
}

func strongestInference(inferences []core.Inference) *core.Inference {
	best := -1
	for index := range inferences {
		if best < 0 || inferenceRank(inferences[index].State) > inferenceRank(inferences[best].State) {
			best = index
		}
	}
	if best < 0 {
		return nil
	}
	return &inferences[best]
}

func inferenceForState(inferences []core.Inference, state core.ResultState) *core.Inference {
	if state == core.ResultInconclusive || state == core.ResultObservation {
		return strongestInference(inferences)
	}
	for index := range inferences {
		if inferences[index].State == state {
			return &inferences[index]
		}
	}
	return nil
}

func inferenceRank(state core.ResultState) int {
	switch state {
	case core.ResultConfirmed:
		return 6
	case core.ResultCandidate:
		return 5
	case core.ResultSuppressed:
		return 4
	case core.ResultObservation:
		return 3
	case core.ResultInconclusive:
		return 2
	case core.ResultHealthy:
		return 1
	default:
		return 0
	}
}

func evidenceReasons(analysis *core.HostAnalysis) []string {
	seen := make(map[string]struct{})
	var reasons []string
	for _, evidence := range analysis.Evidences {
		if evidence.IsNegative || evidence.Type == "HTTP_RESPONSE" || strings.TrimSpace(evidence.Type) == "" {
			continue
		}
		if _, duplicate := seen[evidence.Type]; duplicate {
			continue
		}
		seen[evidence.Type] = struct{}{}
		reasons = append(reasons, evidence.Type)
		if len(reasons) == 6 {
			break
		}
	}
	return reasons
}

func evidenceConfidence(analysis *core.HostAnalysis) int {
	confidence := 0
	for _, evidence := range analysis.Evidences {
		if evidence.Confidence > confidence {
			confidence = evidence.Confidence
		}
	}
	return confidence
}

func inconclusiveReason(analysis *core.HostAnalysis, level string) string {
	if level != LevelUnknown && level != LevelInsufficientEvidence {
		return ""
	}
	for _, observation := range analysis.HTTPObservations {
		message := strings.ToLower(observation.TransportError + " " + observation.ParseError)
		switch {
		case strings.Contains(message, "timeout"), strings.Contains(message, "tempo limite"):
			return "TIMEOUT"
		case strings.Contains(message, "tls"), strings.Contains(message, "x509"), strings.Contains(message, "certificate"):
			return "TLS_ERROR"
		case strings.Contains(message, "connection refused"), strings.Contains(message, "conexão recusada"):
			return "CONNECTION_REFUSED"
		}
	}
	for _, evidence := range analysis.Evidences {
		switch evidence.Type {
		case "NS_SERVFAIL", "DNSSEC_SERVFAIL_INCONCLUSIVE":
			return "DNS_SERVFAIL"
		}
	}
	return "INSUFFICIENT_EVIDENCE"
}
