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
