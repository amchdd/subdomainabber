package finding

import (
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
)

func TestPrimaryMapsGenericHTTPMisconfigurationToHTTP(t *testing.T) {
	analysis := &core.HostAnalysis{
		Host: "app.example.com",
		Evidences: []core.Evidence{
			{Type: "HTTP_RESPONSE"},
			{Type: "HTTP_CSP_MISSING", Description: "CSP is missing"},
			{Type: "HTTP_HSTS_MISSING", Description: "HSTS is missing"},
		},
	}
	context := Primary(analysis)
	if context.Vector != "HTTP" || context.Resource != analysis.Host || context.Evidence.Type != "HTTP_HSTS_MISSING" {
		t.Fatalf("unexpected context: %+v", context)
	}
}

func TestPrimaryUsesZoneForAXFRAndDelegation(t *testing.T) {
	analysis := &core.HostAnalysis{
		Host:       "api.dev.example.com",
		Delegation: &core.DelegationCandidate{Zone: "dev.example.com"},
		Evidences: []core.Evidence{{
			Type:     "DELEGATION_BROKEN",
			Metadata: map[string]string{"zone": "dev.example.com"},
		}},
	}
	context := Primary(analysis)
	if context.Vector != "NS" || context.Resource != "dev.example.com" {
		t.Fatalf("unexpected delegation context: %+v", context)
	}
}

func TestPrimaryMapsCorrelatedVectors(t *testing.T) {
	tests := map[string]string{
		"SNI_CERT_MISMATCH":               "TLS",
		"CAA_ISSUER_MISMATCH":             "CAA",
		"TXT_OWNERSHIP_TOKEN_RESIDUAL":    "TXT",
		"PROVIDER_MIGRATION_DETECTED":     "HISTORY",
		"RELATED_DOMAIN_COOKIE_SCOPE":     "COOKIE",
		"RELATED_DOMAIN_CORS_CREDENTIALS": "CORS",
	}
	for evidenceType, expected := range tests {
		analysis := &core.HostAnalysis{Host: "app.example.com", Evidences: []core.Evidence{{Type: evidenceType}}}
		if context := Primary(analysis); context.Vector != expected {
			t.Fatalf("%s mapeado para %s, esperado %s", evidenceType, context.Vector, expected)
		}
	}
}
