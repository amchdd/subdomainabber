package classification

const (
	LevelTakenOver                      = "TAKEN_OVER"
	LevelConfirmed                      = "CONFIRMED_TAKEOVERABLE"
	LevelTakeoverable                   = "TAKEOVERABLE"
	LevelLikelyTakeoverable             = "LIKELY_TAKEOVERABLE"
	LevelZoneControlConfirmed           = "ZONE_CONTROL_CONFIRMED"
	LevelDelegationClaimabilityVerified = "DELEGATION_CLAIMABILITY_VERIFIED"
	LevelDelegationTakeoverCandidate    = "DELEGATION_TAKEOVER_CANDIDATE"
	LevelDelegationBroken               = "DELEGATION_BROKEN"
	LevelExposed                        = "EXPOSED"
	LevelOrphaned                       = "ORPHANED"
	LevelMisconfigured                  = "MISCONFIGURED"
	LevelUnknown                        = "UNKNOWN"
	LevelInsufficientEvidence           = "INSUFFICIENT_EVIDENCE"
	LevelHealthy                        = "HEALTHY"
)

// RiskRank retorna uma posição de risco estável e monotônica para a classificação.
// Valores desconhecidos são tratados como UNKNOWN e nunca como HEALTHY.
func RiskRank(level string) int {
	switch level {
	case LevelHealthy:
		return 0
	case LevelInsufficientEvidence:
		return 1
	case LevelUnknown, "":
		return 2
	case LevelMisconfigured:
		return 3
	case LevelExposed:
		return 4
	case LevelOrphaned, LevelDelegationBroken:
		return 5
	case LevelLikelyTakeoverable, LevelDelegationTakeoverCandidate:
		return 6
	case LevelTakeoverable:
		return 7
	case LevelConfirmed, LevelDelegationClaimabilityVerified:
		return 8
	case LevelZoneControlConfirmed:
		return 9
	case LevelTakenOver:
		return 10
	default:
		return 2
	}
}
