package evidence

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
)

func TestPlan3FramingExperimentUsesEquivalentPOSTControls(t *testing.T) {
	analysis := mutationAnalysis(t, true, []byte("Access denied"))
	transport := &scriptedRawTransport{responses: []core.RawHTTPObservation{
		{StatusCode: 403, Body: []byte("Access denied"), Complete: true},
		{StatusCode: 404, Body: []byte("The specified bucket does not exist"), Complete: true},
		{StatusCode: 404, Body: []byte("The specified bucket does not exist"), Complete: true},
		{StatusCode: 403, Body: []byte("Access denied"), Complete: true},
	}}
	collector := testFramingCollector(t, "example.com", transport)
	collector.SetMutations([]HTTPMutation{CLTEProbe{}})

	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := transport.callCount(); got != 4 {
		t.Fatalf("calls = %d, want C1/M1/M2/C2 (4)", got)
	}
	for _, index := range []int{0, 3} {
		payload := transport.payloads[index]
		if !bytes.HasPrefix(payload, []byte("POST / HTTP/1.1\r\n")) || bytes.Contains(payload, []byte("Transfer-Encoding:")) {
			t.Fatalf("control %d is not an equivalent normal POST:\n%s", index, payload)
		}
	}
}

func TestPlan3RawRequestIsByteDeterministic(t *testing.T) {
	headers := []RawHeader{{Name: "Host", Value: " example.com"}, {Name: "X-First", Value: "  one"}, {Name: "x-second", Value: "\ttwo"}, {Name: "X-First", Value: " three"}}
	first, err := buildRawRequest("GET", "/", headers, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		next, err := buildRawRequest("GET", "/", headers, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, next) {
			t.Fatalf("request bytes changed between builds:\nfirst=%q\nnext=%q", first, next)
		}
	}
	want := "GET / HTTP/1.1\r\nHost: example.com\r\nX-First:  one\r\nx-second:\ttwo\r\nX-First: three\r\n\r\n"
	if string(first) != want {
		t.Fatalf("request bytes = %q, want %q", first, want)
	}
}

type failingIndependentCollector struct{}

type countingWaiter struct{ calls int }

func (w *countingWaiter) Wait(context.Context) error { w.calls++; return nil }

type delayedCountingWaiter struct {
	calls int
	delay time.Duration
}

func (w *delayedCountingWaiter) Wait(ctx context.Context) error {
	w.calls++
	timer := time.NewTimer(w.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type contextBlockingTransport struct{}

func (contextBlockingTransport) Send(ctx context.Context, _ core.MutationContext, _ []byte) core.RawHTTPObservation {
	<-ctx.Done()
	return core.RawHTTPObservation{TransportError: ctx.Err().Error()}
}

func (failingIndependentCollector) Collect(context.Context, *core.HostAnalysis) error {
	return errors.New("independent failed")
}

func TestPlan3IndependentCollectorErrorIsReturned(t *testing.T) {
	err := NewRegistry([]Collector{failingIndependentCollector{}}).Run(context.Background(), &core.HostAnalysis{Host: "example.com"})
	if err == nil {
		t.Fatal("independent collector error was silently discarded")
	}
}

func TestPlan3ExplicitPortIsInapplicableWhenHostWouldNotChange(t *testing.T) {
	ctx := testMutationContext("example.com:8080")
	ctx.DialPort = 8080
	if (ExplicitPortProbe{}).Applicability(ctx) {
		t.Fatal("ExplicitPortProbe applicable even though Host already contains the same port")
	}
}

func TestPlan3RateLimiterCoversEveryRawRequest(t *testing.T) {
	analysis := mutationAnalysis(t, true, []byte("Access denied"))
	transport := &scriptedRawTransport{responses: []core.RawHTTPObservation{
		{StatusCode: 403, Body: []byte("Access denied"), Complete: true},
		{StatusCode: 403, Body: []byte("Access denied"), Complete: true},
		{StatusCode: 403, Body: []byte("Access denied"), Complete: true},
		{StatusCode: 403, Body: []byte("Access denied"), Complete: true},
	}}
	waiter := &countingWaiter{}
	collector := testFramingCollector(t, "example.com", transport)
	collector.SetRequestLimiter(waiter)
	collector.SetMutations([]HTTPMutation{CLTEProbe{}})
	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if waiter.calls != 4 {
		t.Fatalf("limiter calls = %d, want 4", waiter.calls)
	}
}

func TestPlan3ProbeCapAndGlobalHostTimeout(t *testing.T) {
	t.Run("probe cap", func(t *testing.T) {
		analysis := mutationAnalysis(t, true, []byte("Access denied"))
		response := core.RawHTTPObservation{StatusCode: 403, Body: []byte("Access denied"), Complete: true}
		transport := &scriptedRawTransport{responses: []core.RawHTTPObservation{response, response, response, response}}
		collector := testFramingCollector(t, "example.com", transport)
		collector.SetLimits(1, time.Second)
		collector.SetMutations([]HTTPMutation{CLTEProbe{}, TECLProbe{}})
		if err := collector.Collect(context.Background(), analysis); err != nil {
			t.Fatal(err)
		}
		if transport.callCount() != 4 || len(analysis.MutationResults) != 1 {
			t.Fatalf("calls/results = %d/%d, want 4/1", transport.callCount(), len(analysis.MutationResults))
		}
	})
	t.Run("global timeout cancels transport", func(t *testing.T) {
		analysis := mutationAnalysis(t, true, []byte("Access denied"))
		collector := testFramingCollector(t, "example.com", contextBlockingTransport{})
		collector.SetLimits(1, 30*time.Millisecond)
		collector.SetMutations([]HTTPMutation{CLTEProbe{}})
		started := time.Now()
		if err := collector.Collect(context.Background(), analysis); err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
			t.Fatalf("global timeout was not enforced: %s", elapsed)
		}
		if got := analysis.MutationResults[0].Outcome; got != core.MutationFramingTransportFailure {
			t.Fatalf("outcome = %s", got)
		}
	})
}

func TestMutationNetworkBudgetExcludesLimiterQueueTime(t *testing.T) {
	analysis := mutationAnalysis(t, true, []byte("Access denied"))
	response := core.RawHTTPObservation{StatusCode: 403, Body: []byte("Access denied"), Complete: true}
	transport := &scriptedRawTransport{responses: []core.RawHTTPObservation{response, response, response, response}}
	waiter := &delayedCountingWaiter{delay: 20 * time.Millisecond}
	collector := testFramingCollector(t, "example.com", transport)
	collector.SetLimits(1, 10*time.Millisecond)
	collector.SetRequestLimiter(waiter)
	collector.SetMutations([]HTTPMutation{CLTEProbe{}})
	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if waiter.calls != 4 || transport.callCount() != 4 {
		t.Fatalf("limiter waiting consumed network budget: waits=%d calls=%d", waiter.calls, transport.callCount())
	}
}

func TestFramingCollectorEnforcesAuthorityAllowlist(t *testing.T) {
	analysis := mutationAnalysis(t, true, []byte("Access denied"))
	transport := &scriptedRawTransport{}
	collector := testFramingCollector(t, "allowed.example", transport)
	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if transport.callCount() != 0 || len(analysis.MutationResults) != 0 {
		t.Fatalf("non-allowlisted framing executed: calls=%d", transport.callCount())
	}
}

func testFramingCollector(t *testing.T, authority string, transport HTTPRawTransport) *HTTPMutatorCollector {
	t.Helper()
	collector, err := NewHTTPFramingCollector(time.Second, []string{authority})
	if err != nil {
		t.Fatal(err)
	}
	collector.SetTransport(transport)
	return collector
}
