package core

import (
	"fmt"
	"sync"
	"testing"
)

func TestHostAnalysisInitializesMutexBeforeConcurrentWrites(t *testing.T) {
	analysis := &HostAnalysis{Host: "example.test"}
	const workers = 64

	start := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(workers)
	for index := 0; index < workers; index++ {
		index := index
		go func() {
			defer wait.Done()
			<-start
			analysis.AddEvidence(Evidence{Type: fmt.Sprintf("EVIDENCE_%d", index)})
		}()
	}
	close(start)
	wait.Wait()

	if len(analysis.Evidences) != workers {
		t.Fatalf("evidências gravadas = %d; esperado %d", len(analysis.Evidences), workers)
	}
}
