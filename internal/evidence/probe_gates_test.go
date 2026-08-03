package evidence

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
)

type countingTLSDialer struct{ calls int }

func (dialer *countingTLSDialer) DialTLSContext(context.Context, string, string, *tls.Config) (*tls.ConnectionState, error) {
	dialer.calls++
	return nil, errors.New("unexpected dial")
}

func TestTLSAndRedirectSkipHostsWithoutUsableBaseline(t *testing.T) {
	analysis := &core.HostAnalysis{Host: "missing.example.com"}
	dialer := &countingTLSDialer{}
	tlsCollector := NewTLSCollector(nil, time.Second)
	tlsCollector.SetDialer(dialer)
	if err := tlsCollector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if dialer.calls != 0 {
		t.Fatalf("TLS performed %d unroutable dials", dialer.calls)
	}

	security := NewHttpSecurityCollectorForChecks(false, true)
	var requests int
	security.client.Transport = impactRoundTripperFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return nil, errors.New("unexpected request")
	})
	if err := security.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if requests != 0 {
		t.Fatalf("redirect collector performed %d requests without baseline", requests)
	}
}

func TestHTTPProbeSupportsAAAAOnlyHost(t *testing.T) {
	collector := NewHTTPCollector(nil, time.Second, "", false, "", false)
	if !collector.ShouldProbeHTTP(&core.HostAnalysis{DNS: core.DNSRecordSet{AAAA: []string{"2001:db8::10"}}}) {
		t.Fatal("AAAA-only host was excluded from HTTP probing")
	}
}
