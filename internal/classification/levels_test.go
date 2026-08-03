package classification

import "testing"

func TestRiskRankCoversEveryClassification(t *testing.T) {
	ordered := []string{
		LevelHealthy,
		LevelInsufficientEvidence,
		LevelUnknown,
		LevelMisconfigured,
		LevelExposed,
		LevelOrphaned,
		LevelLikelyTakeoverable,
		LevelTakeoverable,
		LevelConfirmed,
		LevelZoneControlConfirmed,
		LevelTakenOver,
	}

	for i := 1; i < len(ordered); i++ {
		if RiskRank(ordered[i]) <= RiskRank(ordered[i-1]) {
			t.Fatalf("%s must rank above %s", ordered[i], ordered[i-1])
		}
	}

	if RiskRank(LevelDelegationBroken) != RiskRank(LevelOrphaned) {
		t.Fatal("broken delegation and orphaned resource should have equal triage risk")
	}
	if RiskRank(LevelDelegationTakeoverCandidate) != RiskRank(LevelLikelyTakeoverable) {
		t.Fatal("delegation and CNAME takeover candidates should have equal triage risk")
	}
	if RiskRank(LevelDelegationClaimabilityVerified) != RiskRank(LevelConfirmed) {
		t.Fatal("actively verified delegation and CNAME findings should have equal risk")
	}
	if RiskRank("FUTURE_LEVEL") != RiskRank(LevelUnknown) {
		t.Fatal("unknown classifications must not silently rank as healthy")
	}
}
