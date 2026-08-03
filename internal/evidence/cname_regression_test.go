package evidence

import (
	"context"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/pkg/signatures"
)

func TestCNAMECollectorRejectsUnsafeSuffixMatches(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		pattern string
	}{
		{name: "label boundary", target: "evilgithub.io", pattern: "github.io"},
		{name: "empty pattern", target: "user.github.io", pattern: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := NewCNAMECollector(nil, []signatures.Fingerprint{
				{
					Service:    "GitHub Pages",
					CNames:     []string{tt.pattern},
					CheckType:  "cname",
					Vulnerable: true,
				},
			})
			analysis := &core.HostAnalysis{
				Host: "foo.example.com",
				DNS: core.DNSRecordSet{
					CNAME: []string{tt.target},
					A:     []string{"192.0.2.1"},
				},
			}

			if err := collector.Collect(context.Background(), analysis); err != nil {
				t.Fatalf("Collect returned an unexpected error: %v", err)
			}
			for _, evidence := range analysis.Evidences {
				if evidence.Type == "CNAME_PROVIDER_MATCH" {
					t.Fatalf("target %q must not match pattern %q", tt.target, tt.pattern)
				}
			}
		})
	}
}

func TestCNAMETransportFailureNeverBecomesDangling(t *testing.T) {
	for _, status := range []core.DNSStatus{
		core.DNSStatusTimeout,
		core.DNSStatusServFail,
		core.DNSStatusRefused,
		core.DNSStatusError,
	} {
		evidenceType, _, weight, _ := cnameResolutionEvidence(status, "AWS/S3")
		if evidenceType == "CNAME_DANGLING" || weight != 0 {
			t.Fatalf("%s became %s with weight %d", status, evidenceType, weight)
		}
	}
	for _, status := range []core.DNSStatus{core.DNSStatusNXDomain, core.DNSStatusNoData} {
		evidenceType, _, _, _ := cnameResolutionEvidence(status, "AWS/S3")
		if evidenceType != "CNAME_DANGLING" {
			t.Fatalf("%s did not become conclusive dangling: %s", status, evidenceType)
		}
	}
}
