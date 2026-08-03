package ratelimit

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type delayedWaiter struct {
	delay time.Duration
}

func (waiter delayedWaiter) Wait(ctx context.Context) error {
	timer := time.NewTimer(waiter.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (function roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestTimedTransportStartsTimeoutAfterLimiterPermit(t *testing.T) {
	var reachedBase atomic.Bool
	transport := NewTimedTransport(
		delayedWaiter{delay: 80 * time.Millisecond},
		roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			reachedBase.Store(true)
			select {
			case <-request.Context().Done():
				return nil, request.Context().Err()
			case <-time.After(20 * time.Millisecond):
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("ok")),
					Request:    request,
				}, nil
			}
		}),
		50*time.Millisecond,
	)
	client := &http.Client{Transport: transport}

	started := time.Now()
	response, err := client.Get("http://example.test")
	if err != nil {
		t.Fatalf("request failed while waiting for permit: %v", err)
	}
	defer response.Body.Close()
	if !reachedBase.Load() {
		t.Fatal("base transport was not reached")
	}
	if elapsed := time.Since(started); elapsed < 90*time.Millisecond {
		t.Fatalf("limiter wait was not observed: %s", elapsed)
	}
}

func TestTimedTransportEnforcesNetworkTimeout(t *testing.T) {
	transport := NewTimedTransport(
		nil,
		roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			<-request.Context().Done()
			return nil, request.Context().Err()
		}),
		20*time.Millisecond,
	)
	_, err := (&http.Client{Transport: transport}).Get("http://example.test")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected network deadline, got %v", err)
	}
}

func TestLimiterStatsTrackWaitingAndGranted(t *testing.T) {
	limiter := New(1)
	if err := limiter.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = limiter.Wait(ctx)
	}()

	deadline := time.Now().Add(time.Second)
	for limiter.Stats().Waiting == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	stats := limiter.Stats()
	if stats.Granted != 1 || stats.Waiting != 1 {
		t.Fatalf("unexpected stats while queued: %+v", stats)
	}
	cancel()
	<-done
	if limiter.Stats().Waiting != 0 {
		t.Fatalf("waiter counter was not released: %+v", limiter.Stats())
	}
}
