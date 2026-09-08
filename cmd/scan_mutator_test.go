package cmd

import (
	"strings"
	"testing"
	"time"

	"github.com/amchdd/subdomainabber/internal/evidence"
)

func TestCheckAllDoesNotEnableExperimentalMutator(t *testing.T) {
	previousEvasion := checkEvasion
	previousFraming := checkFraming
	previousAggressive := aggressive
	previousVHost := checkVHost
	previousWebDeps := checkWebDeps
	previousFollow := followRedirects
	previousSNI := checkSNI
	previousOrigin := checkOrigin
	previousSANPivot := pivotSAN
	t.Cleanup(func() {
		checkEvasion = previousEvasion
		checkFraming = previousFraming
		aggressive = previousAggressive
		checkVHost = previousVHost
		checkWebDeps = previousWebDeps
		followRedirects = previousFollow
		checkSNI = previousSNI
		checkOrigin = previousOrigin
		pivotSAN = previousSANPivot
	})
	checkEvasion = false
	checkFraming = false
	aggressive = false
	pivotSAN = false

	enableCheckAllModules()
	if checkEvasion {
		t.Fatal("--check-all enabled HTTP evasion probes")
	}
	if checkFraming {
		t.Fatal("--check-all enabled high-risk framing")
	}
	if aggressive {
		t.Fatal("--check-all enabled real auto-claim")
	}
	if !checkVHost || !checkWebDeps || !followRedirects {
		t.Fatal("--check-all não habilitou as análises HTTP seguras")
	}
	if pivotSAN {
		t.Fatal("--check-all habilitou pivô SAN sem allowlist")
	}
	if !checkSNI || !checkOrigin {
		t.Fatal("--check-all não habilitou as análises TLS seguras")
	}
}

func TestDefaultHTTPAnalysisFlags(t *testing.T) {
	for _, name := range []string{"follow-redirects", "check-vhost", "check-web-deps"} {
		flag := scanCmd.Flags().Lookup(name)
		if flag == nil || flag.DefValue != "true" {
			t.Fatalf("--%s não está habilitada por padrão", name)
		}
	}
	if flag := scanCmd.Flags().Lookup("check-sni"); flag == nil || flag.DefValue != "false" {
		t.Fatal("--check-sni deve continuar opcional para a variante alternativa")
	}
}

func TestFramingRequiresSeparateConfirmationAndAllowlist(t *testing.T) {
	if collector, err := newFramingCollectorIfAuthorized(false, false, "", time.Second); err != nil || collector != nil {
		t.Fatalf("disabled framing = %#v, %v", collector, err)
	}
	if _, err := newFramingCollectorIfAuthorized(true, false, "lab.example", time.Second); err == nil {
		t.Fatal("framing accepted without controlled-environment confirmation")
	}
	if _, err := newFramingCollectorIfAuthorized(true, true, "", time.Second); err == nil {
		t.Fatal("framing accepted without allowlist")
	}
	collector, err := newFramingCollectorIfAuthorized(true, true, "lab.example", time.Second)
	if err != nil || collector == nil || collector.Name() != "HTTP_FRAMING_LAB" {
		t.Fatalf("authorized framing collector = %#v, %v", collector, err)
	}
}

func TestFramingFlagWarnsAboutControlledAuthorization(t *testing.T) {
	for _, name := range []string{"check-framing", "framing-confirm-controlled", "framing-allowlist"} {
		if scanCmd.Flags().Lookup(name) == nil {
			t.Fatalf("--%s flag is missing", name)
		}
	}
	usage := strings.ToLower(scanCmd.Flags().Lookup("check-framing").Usage)
	if !strings.Contains(usage, "controlado") || !strings.Contains(usage, "autorizado") {
		t.Fatalf("unsafe framing help: %q", usage)
	}
}

func TestEvasionExplicitlyRegistersMutator(t *testing.T) {
	collectors := appendHTTPMutatorIfEnabled(nil, false, nil, time.Second)
	if len(collectors) != 0 {
		t.Fatalf("disabled mutator registered %d collectors", len(collectors))
	}
	collectors = appendHTTPMutatorIfEnabled(nil, true, nil, time.Second)
	if len(collectors) != 1 {
		t.Fatalf("enabled mutator registered %d collectors", len(collectors))
	}
	phased, ok := collectors[0].(evidence.PhasedCollector)
	if !ok || phased.Phase() != evidence.PhaseHTTPMutation {
		t.Fatalf("registered collector is not in the mutation phase: %#v", collectors[0])
	}
}

func TestEvasionHelpRequiresAuthorizationAndDoesNotClaimSmuggling(t *testing.T) {
	flag := scanCmd.Flags().Lookup("evasion")
	if flag == nil {
		t.Fatal("--evasion flag is missing")
	}
	usage := strings.ToLower(flag.Usage)
	if !strings.Contains(usage, "autoriza") || strings.Contains(usage, "smuggling") {
		t.Fatalf("unexpected --evasion help: %q", flag.Usage)
	}
	if legacy := scanCmd.Flags().Lookup("check-exotic"); legacy != nil {
		t.Fatal("legacy --check-exotic flag is still registered")
	}
}
