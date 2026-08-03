package verify

import (
	"context"
	"reflect"
	"testing"

	"github.com/amchdd/subdomainabber/internal/classification"
	"github.com/amchdd/subdomainabber/internal/core"
)

func TestGetTransitionSeverityUsesAllClassificationLevels(t *testing.T) {
	tests := []struct {
		name string
		old  string
		new  string
		want string
	}{
		{"unchanged", classification.LevelUnknown, classification.LevelUnknown, "NONE"},
		{"coverage loss", classification.LevelHealthy, classification.LevelUnknown, "MEDIUM"},
		{"broken delegation", classification.LevelUnknown, classification.LevelDelegationBroken, "HIGH"},
		{"takeover candidate", classification.LevelUnknown, classification.LevelDelegationTakeoverCandidate, "HIGH"},
		{"claimability verified", classification.LevelDelegationTakeoverCandidate, classification.LevelDelegationClaimabilityVerified, "CRITICAL"},
		{"zone control confirmed", classification.LevelDelegationClaimabilityVerified, classification.LevelZoneControlConfirmed, "CRITICAL"},
		{"fixed", classification.LevelTakenOver, classification.LevelHealthy, "LOW"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetTransitionSeverity(tt.old, tt.new); got != tt.want {
				t.Fatalf("GetTransitionSeverity(%q, %q) = %q, want %q", tt.old, tt.new, got, tt.want)
			}
		})
	}
}

func TestVerifyRefusesHistoricalRecordWithoutCompatibleProfile(t *testing.T) {
	engine := &Engine{signatureDigest: "sha256:current"}
	result, err := engine.Verify(context.Background(), &core.HostAnalysis{Host: "legacy.example.com", Classification: classification.LevelOrphaned})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != Incomplete || result.NewClassification != classification.LevelOrphaned {
		t.Fatalf("resultado incompatível = %#v", result)
	}
}

func TestProfileCompatibilityDetectsCatalogAndUnsafeModes(t *testing.T) {
	engine := &Engine{signatureDigest: "sha256:current"}
	compatible := &core.ScanProfile{Version: 1, SignatureDigest: "sha256:current"}
	if reason := engine.profileCompatibilityError(compatible); reason != "" {
		t.Fatalf("perfil compatível recusado: %s", reason)
	}

	changed := *compatible
	changed.SignatureDigest = "sha256:old"
	if reason := engine.profileCompatibilityError(&changed); reason == "" {
		t.Fatal("mudança no catálogo não foi detectada")
	}
	framing := *compatible
	framing.CheckFraming = true
	if reason := engine.profileCompatibilityError(&framing); reason == "" {
		t.Fatal("framing foi aceito para repetição automática")
	}
	aggressive := *compatible
	aggressive.Aggressive = true
	if reason := engine.profileCompatibilityError(&aggressive); reason == "" {
		t.Fatal("reivindicação automática foi aceita para repetição")
	}
}

func TestVectorDifferencesAreNormalizedAndDeterministic(t *testing.T) {
	missing, unexpected := vectorDifferences(
		[]string{"HTTP", "dns", "HTTP"},
		[]string{"DNS", "TLS", "  tls  "},
	)
	if !reflect.DeepEqual(missing, []string{"HTTP"}) || !reflect.DeepEqual(unexpected, []string{"TLS"}) {
		t.Fatalf("diferenças = ausentes %#v, adicionais %#v", missing, unexpected)
	}
}

func TestDetermineStateChangePreservesEqualRiskClassificationChanges(t *testing.T) {
	engine := &Engine{}
	if got := engine.determineStateChange(classification.LevelOrphaned, classification.LevelDelegationBroken); got != Changed {
		t.Fatalf("equal-risk classification change = %q, want %q", got, Changed)
	}
	if got := engine.determineStateChange(classification.LevelUnknown, classification.LevelUnknown); got != Unchanged {
		t.Fatalf("identical classification = %q, want %q", got, Unchanged)
	}
}
