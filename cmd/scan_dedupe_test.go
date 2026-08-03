package cmd

import (
	"sync"
	"testing"

	"github.com/amchdd/subdomainabber/internal/classification"
)

func TestScanFindingDeduperAllowsOneFindingPerZone(t *testing.T) {
	deduper := newScanFindingDeduper()
	var firstCount int
	var mutex sync.Mutex
	var waitGroup sync.WaitGroup
	for index := 0; index < 20; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			if deduper.First("NS|projects.example.com") {
				mutex.Lock()
				firstCount++
				mutex.Unlock()
			}
		}()
	}
	waitGroup.Wait()
	if firstCount != 1 {
		t.Fatalf("first findings = %d, want 1", firstCount)
	}
	if !deduper.First("NS|other.example.com") {
		t.Fatal("different zone was incorrectly suppressed")
	}
}

func TestHumanDefaultTreatsHealthyAndInconclusiveAsNonActionable(t *testing.T) {
	for _, level := range []string{
		classification.LevelHealthy,
		classification.LevelUnknown,
		classification.LevelInsufficientEvidence,
	} {
		if isActionableClassification(level) {
			t.Fatalf("%s was considered actionable", level)
		}
	}
	if !isActionableClassification(classification.LevelLikelyTakeoverable) {
		t.Fatal("likely takeover was suppressed")
	}
}

func TestCLISeverityFilterUsesDiscordSeverityMapping(t *testing.T) {
	if cliSeverityAllows(classification.LevelMisconfigured, "medium") {
		t.Fatal("low misconfiguration passed medium CLI filter")
	}
	if !cliSeverityAllows(classification.LevelLikelyTakeoverable, "medium") {
		t.Fatal("likely takeover was hidden by medium CLI filter")
	}
	if !cliSeverityAllows(classification.LevelMisconfigured, "") {
		t.Fatal("empty CLI filter changed default visibility")
	}
}
