package evidence

import (
	"net/http"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/pkg/signatures"
)

func TestTakeoverFingerprintEligibilityIsStructured(t *testing.T) {
	status := 404
	signature := signatures.Fingerprint{Service: "AWS/S3", CNames: []string{"s3.amazonaws.com"}, Fingerprint: "The specified bucket does not exist", HTTPStatus: &status, Headers: map[string]string{"X-Provider": "s3"}, Vulnerable: true, Status: "Vulnerable"}
	candidate := core.ProviderCandidate{ProviderID: "aws_s3", Service: "AWS/S3", CNAME: "bucket.s3.amazonaws.com"}
	observation := core.RawHTTPObservation{StatusCode: 404, Headers: http.Header{"X-Provider": []string{"aws-s3"}}, Body: []byte(signature.Fingerprint), Complete: true}
	rule, eligible := eligibleTakeoverFingerprint(&signature, candidate, observation)
	if !eligible || rule.RuleID == "" || rule.ProviderID != candidate.ProviderID || rule.Claimability != "potentially_claimable" {
		t.Fatalf("eligible rule = %#v, %v", rule, eligible)
	}

	wrongStatus := observation
	wrongStatus.StatusCode = 200
	if _, ok := eligibleTakeoverFingerprint(&signature, candidate, wrongStatus); ok {
		t.Fatal("wrong status accepted")
	}
	missingHeader := observation
	missingHeader.Headers = nil
	if _, ok := eligibleTakeoverFingerprint(&signature, candidate, missingHeader); ok {
		t.Fatal("missing required header accepted")
	}
	incomplete := observation
	incomplete.Complete = false
	incomplete.ParseError = "corpo truncado"
	if _, ok := eligibleTakeoverFingerprint(&signature, candidate, incomplete); ok {
		t.Fatal("uma resposta HTTP incompleta foi aceita")
	}
	wrongCandidate := candidate
	wrongCandidate.ProviderID = "other"
	if _, ok := eligibleTakeoverFingerprint(&signature, wrongCandidate, observation); ok {
		t.Fatal("wrong provider accepted")
	}
	generic := signature
	generic.Fingerprint = "404 Not Found"
	observation.Body = []byte(generic.Fingerprint)
	if _, ok := eligibleTakeoverFingerprint(&generic, candidate, observation); ok {
		t.Fatal("generic fingerprint accepted")
	}
}

func TestFingerprintEligibilityDoesNotDependOnLocalizedStatus(t *testing.T) {
	status := 404
	signature := signatures.Fingerprint{
		Service: "AWS/S3", CNames: []string{"s3.amazonaws.com"},
		Fingerprint: "The specified bucket does not exist", HTTPStatus: &status,
		Vulnerable: true, Status: "Recurso vulnerável conforme a referência",
	}
	candidate := core.ProviderCandidate{ProviderID: providerID(signature.Service), CNAME: "bucket.s3.amazonaws.com"}
	observation := core.RawHTTPObservation{StatusCode: status, Body: []byte(signature.Fingerprint), Complete: true}
	if _, eligible := eligibleTakeoverFingerprint(&signature, candidate, observation); !eligible {
		t.Fatal("o texto localizado de status alterou a elegibilidade estruturada")
	}
}
