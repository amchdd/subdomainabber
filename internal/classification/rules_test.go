package classification

import (
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
)

func TestClassifyDoesNotPromoteUnknownCNAMEWithHTTP404(t *testing.T) {
	analysis := &core.HostAnalysis{
		Host: "foo.example.com",
		DNS: core.DNSRecordSet{
			CNAME: []string{"external.example.net"},
		},
		Evidences: []core.Evidence{
			{Type: "HTTP_STATUS_404", Source: "https"},
		},
	}

	classification := Classify(analysis)
	if classification == LevelLikelyTakeoverable || classification == LevelTakeoverable || classification == LevelConfirmed || classification == LevelTakenOver {
		t.Fatalf("unknown CNAME plus HTTP 404 must not be classified as takeover; got %s", classification)
	}
}

func TestClassifyUsesOnlyConfirmedProviderBoundMutationFingerprint(t *testing.T) {
	tests := []struct {
		name           string
		mutationSource string
		confirmations  string
		want           string
	}{
		{name: "same provider confirmed", mutationSource: "AWS/S3", confirmations: "2", want: LevelLikelyTakeoverable},
		{name: "different provider", mutationSource: "GitHub Pages", confirmations: "2", want: LevelUnknown},
		{name: "single observation", mutationSource: "AWS/S3", confirmations: "1", want: LevelUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := &core.HostAnalysis{
				Host: "assets.example.com",
				Evidences: []core.Evidence{
					{Type: "CNAME_PROVIDER_MATCH", Source: "AWS/S3", Metadata: map[string]string{"provider_id": "aws_s3", "matched_cname": "bucket.s3.amazonaws.com"}},
					{
						Type:   "HTTP_MUTATION_REVEALED_PROVIDER_FINGERPRINT",
						Source: tt.mutationSource,
						Metadata: map[string]string{
							"confirmations":       tt.confirmations,
							"provider_id":         "aws_s3",
							"cname":               "bucket.s3.amazonaws.com",
							"rule_id":             "aws_s3-http-test",
							"matched_fingerprint": "The specified bucket does not exist",
						},
					},
				},
			}
			if got := Classify(analysis); got != tt.want {
				t.Fatalf("Classify() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestPlan3Provider404NeedsExactProviderFingerprint(t *testing.T) {
	tests := []struct {
		name  string
		extra []core.Evidence
		want  string
	}{
		{name: "known provider generic 404", extra: []core.Evidence{{Type: "HTTP_STATUS_404", Source: "https"}}, want: LevelUnknown},
		{name: "known provider WAF 404", extra: []core.Evidence{{Type: "HTTP_STATUS_404", Source: "https"}, {Type: "CDN_DETECTED", Source: "cloudflare"}}, want: LevelUnknown},
		{name: "exact provider fingerprint", extra: []core.Evidence{{Type: "HTTP_BODY_MATCH", Source: "AWS/S3", Metadata: map[string]string{"provider_id": "aws_s3", "matched_cname": "bucket.s3.amazonaws.com", "rule_id": "aws_s3-http-test", "matched_fingerprint": "The specified bucket does not exist"}}}, want: LevelLikelyTakeoverable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evidences := []core.Evidence{{Type: "CNAME_PROVIDER_MATCH", Source: "AWS/S3", Metadata: map[string]string{"provider_id": "aws_s3", "matched_cname": "bucket.s3.amazonaws.com"}}}
			evidences = append(evidences, tt.extra...)
			analysis := &core.HostAnalysis{Host: "bucket.example.com", Evidences: evidences}
			if got := Classify(analysis); got != tt.want {
				t.Fatalf("Classify() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestRemainingGenericProviderFingerprintDoesNotPromote(t *testing.T) {
	analysis := &core.HostAnalysis{Host: "site.example.com", Evidences: []core.Evidence{
		{Type: "CNAME_PROVIDER_MATCH", Source: "Generic Provider", Metadata: map[string]string{"provider_id": "generic_provider", "matched_cname": "site.provider.example"}},
		{Type: "HTTP_BODY_MATCH", Source: "Generic Provider", Metadata: map[string]string{"provider_id": "generic_provider", "matched_cname": "site.provider.example", "matched_fingerprint": "404 Not Found"}},
	}}
	if got := Classify(analysis); got != LevelUnknown {
		t.Fatalf("generic fingerprint classification = %s, want UNKNOWN", got)
	}
}

func TestOperationalSignalsNeverPromoteToTakeover(t *testing.T) {
	tests := []struct {
		name      string
		evidences []core.Evidence
		score     int
	}{
		{name: "AXFR", evidences: []core.Evidence{{Type: "DNS_AXFR_ALLOWED"}}},
		{name: "dead nameservers", evidences: []core.Evidence{{Type: "NS_ALL_DEAD"}}},
		{name: "self-signed TLS", evidences: []core.Evidence{{Type: "CNAME_PROVIDER_MATCH", Source: "Provider"}, {Type: "TLS_SELF_SIGNED"}}},
		{name: "generic score", evidences: []core.Evidence{{Type: "UNRELATED_HIGH_WEIGHT"}}, score: 100},
		{name: "numeric verification only", evidences: []core.Evidence{{Type: "UNRELATED"}}, score: 100},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := &core.HostAnalysis{Host: "signal.example.com", Evidences: tt.evidences, RiskScore: tt.score}
			if tt.name == "numeric verification only" {
				analysis.VerificationScore = 100
			}
			got := Classify(analysis)
			if got == LevelLikelyTakeoverable || got == LevelTakeoverable || got == LevelConfirmed || got == LevelTakenOver {
				t.Fatalf("operational signal promoted to %s", got)
			}
		})
	}
}

func TestStructuredActiveVerificationAndClaimHaveDistinctLevels(t *testing.T) {
	verified := &core.HostAnalysis{
		VerificationScore:  100,
		ActiveVerification: &core.VerificationResult{Provider: "AWS/S3", Verified: true, ControlProven: true, Confidence: 100},
	}
	if got := Classify(verified); got != LevelConfirmed {
		t.Fatalf("structured active verification = %s, want %s", got, LevelConfirmed)
	}
	claimed := &core.HostAnalysis{Evidences: []core.Evidence{{Type: "CLAIM_SUCCESS", Source: "aws_s3"}}}
	if got := Classify(claimed); got != LevelTakenOver {
		t.Fatalf("proven claim = %s, want %s", got, LevelTakenOver)
	}
}

func TestProviderFingerprintDoesNotBecomeConfirmedControl(t *testing.T) {
	analysis := &core.HostAnalysis{
		VerificationScore:  90,
		ActiveVerification: &core.VerificationResult{Provider: "GitHub Pages", Verified: true, Confidence: 90},
		Evidences:          []core.Evidence{{Type: "HTTP_RESPONSE", Metadata: map[string]string{"status": "404"}}},
	}
	if got := Classify(analysis); got == LevelConfirmed || got == LevelTakenOver {
		t.Fatalf("assinatura do provedor foi promovida indevidamente para %s", got)
	}
}

func TestHTTP200WithoutIndependentSignalIsInsufficient(t *testing.T) {
	analysis := &core.HostAnalysis{Evidences: []core.Evidence{
		{Type: "HTTP_RESPONSE", Source: "https", Metadata: map[string]string{"status": "200"}},
		{Type: "HTTP_OK_ACTIVE", Source: "https"},
	}}
	if got := Classify(analysis); got != LevelInsufficientEvidence {
		t.Fatalf("HTTP 200 isolado = %s, esperado %s", got, LevelInsufficientEvidence)
	}
}

func TestHTTPWithUnvalidatedTLSNameRemainsInsufficient(t *testing.T) {
	analysis := &core.HostAnalysis{Evidences: []core.Evidence{
		{Type: "HTTP_RESPONSE", Source: "https", Metadata: map[string]string{"status": "200"}},
		{Type: "TLS_SAN_MATCH", Source: "TLS", IsNegative: true},
	}}
	if got := Classify(analysis); got != LevelInsufficientEvidence {
		t.Fatalf("HTTP com correspondência TLS sem cadeia validada = %s, esperado %s", got, LevelInsufficientEvidence)
	}
}

func TestNoEvidenceIsInsufficientRatherThanHealthy(t *testing.T) {
	if got := Classify(&core.HostAnalysis{}); got != LevelInsufficientEvidence {
		t.Fatalf("empty analysis = %s, want %s", got, LevelInsufficientEvidence)
	}
}

func TestContextOnlyEvidenceIsInsufficientRatherThanUnknown(t *testing.T) {
	analysis := &core.HostAnalysis{Evidences: []core.Evidence{
		{Type: "NS_PROVIDER_MATCH", Confidence: 90},
		{Type: "DNSSEC_ARTIFACTS_OBSERVED", Confidence: 100},
	}}
	if got := Classify(analysis); got != LevelInsufficientEvidence {
		t.Fatalf("context-only evidence = %s, want %s", got, LevelInsufficientEvidence)
	}
}

func TestDelegationStateMachineDoesNotBecomeGenericTakeover(t *testing.T) {
	tests := []struct{ evidenceType, want string }{
		{"DELEGATION_BROKEN", LevelDelegationBroken},
		{"DELEGATION_TAKEOVER_CANDIDATE", LevelDelegationTakeoverCandidate},
		{"DELEGATION_CLAIMABILITY_VERIFIED", LevelDelegationClaimabilityVerified},
		{"ZONE_CONTROL_CONFIRMED", LevelZoneControlConfirmed},
	}
	for _, test := range tests {
		analysis := &core.HostAnalysis{Evidences: []core.Evidence{{Type: test.evidenceType}}}
		if got := Classify(analysis); got != test.want {
			t.Fatalf("%s = %s, want %s", test.evidenceType, got, test.want)
		}
	}
}

func TestFailedRoute53NameserverMatchDowngradesCandidate(t *testing.T) {
	analysis := &core.HostAnalysis{Evidences: []core.Evidence{
		{Type: "DELEGATION_TAKEOVER_CANDIDATE"},
		{Type: "DELEGATION_CLAIMABILITY_NOT_DEMONSTRATED", IsNegative: true},
	}}
	if got := Classify(analysis); got != LevelDelegationBroken {
		t.Fatalf("failed active NS match = %s, want %s", got, LevelDelegationBroken)
	}
}

func TestBrokenNonCNAMEVectorsRemainMisconfigurations(t *testing.T) {
	for _, evidenceType := range []string{"MX_BROKEN", "SRV_BROKEN", "SPF_BROKEN_INCLUDE"} {
		analysis := &core.HostAnalysis{Evidences: []core.Evidence{{Type: evidenceType}}}
		if got := Classify(analysis); got != LevelMisconfigured {
			t.Fatalf("%s = %s", evidenceType, got)
		}
	}
}

func TestAXFRIsExposureNotTakeover(t *testing.T) {
	analysis := &core.HostAnalysis{Evidences: []core.Evidence{{Type: "DNS_AXFR_ALLOWED"}}}
	if got := Classify(analysis); got != LevelExposed {
		t.Fatalf("AXFR = %s, want %s", got, LevelExposed)
	}
}
