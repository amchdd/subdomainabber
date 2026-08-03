package fingerprint

import (
	"strings"
	"testing"

	"github.com/amchdd/subdomainabber/pkg/signatures"
)

func TestValidateRejectsEmptyCNAMEPattern(t *testing.T) {
	report := Validate([]signatures.Fingerprint{
		{
			Service:     "Invalid",
			CNames:      []string{""},
			Fingerprint: "Not Found",
			CheckType:   "cname",
			Vulnerable:  true,
		},
	})

	if report.SchemaErrors == 0 || !report.HasFatalErrors() {
		t.Fatalf("empty CNAME pattern must be a fatal schema error: %#v", report)
	}
}

func TestValidateReportsProviderScopedFingerprintCollisionWithoutMakingItFatal(t *testing.T) {
	report := Validate([]signatures.Fingerprint{
		{Service: "Provider A", CNames: []string{"a.provider.test"}, Fingerprint: "NXDOMAIN", CheckType: "cname", Confidence: 80},
		{Service: "Provider B", CNames: []string{"b.provider.test"}, Fingerprint: "NXDOMAIN", CheckType: "cname", Confidence: 80},
	})
	if report.Collisions != 1 || len(report.CollisionInfo) != 1 {
		t.Fatalf("collision was not reported: %#v", report)
	}
	if report.HasFatalErrors() {
		t.Fatalf("provider-scoped collision was treated as fatal: %#v", report)
	}
}

func TestValidateReportsTheInvalidVectorConfidence(t *testing.T) {
	report := Validate([]signatures.Fingerprint{
		{
			Service:         "Invalid TXT confidence",
			CheckType:       "txt",
			TXTFingerprints: []string{"verify-token"},
			TXTConfidence:   101,
		},
	})
	if report.ConfidenceErr != 1 {
		t.Fatalf("confidence errors = %d, want 1", report.ConfidenceErr)
	}
	if len(report.Errors) == 0 || !strings.Contains(report.Errors[len(report.Errors)-1], "101") {
		t.Fatalf("error does not identify the invalid vector confidence: %#v", report.Errors)
	}
}
