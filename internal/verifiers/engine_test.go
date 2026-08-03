package verifiers

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
)

type recordingVerifier struct {
	name  string
	calls atomic.Int32
}

func (verifier *recordingVerifier) Name() string { return verifier.name }
func (verifier *recordingVerifier) Verify(context.Context, *core.HostAnalysis) (*core.VerificationResult, error) {
	verifier.calls.Add(1)
	return nil, nil
}

func TestTakeoverEngineRunsOnlyProviderCompatibleVerifiers(t *testing.T) {
	github := &recordingVerifier{name: "GitHub Pages"}
	heroku := &recordingVerifier{name: "Heroku"}
	cloudfront := &recordingVerifier{name: "AWS CloudFront"}
	engine := &Engine{takeoverVerifiers: []Verifier{github, heroku, cloudfront}}
	analysis := &core.HostAnalysis{Host: "docs.example.com", Classification: "LIKELY_TAKEOVERABLE"}
	analysis.AddProviderCandidate(core.ProviderCandidate{ProviderID: "github_takeover_detection", Service: "Github Takeover Detection", CNAME: "user.github.io"})

	engine.Run(context.Background(), analysis)

	if github.calls.Load() != 1 {
		t.Fatalf("GitHub calls = %d, want 1", github.calls.Load())
	}
	if heroku.calls.Load() != 0 || cloudfront.calls.Load() != 0 {
		t.Fatalf("unrelated verifier calls: heroku=%d cloudfront=%d", heroku.calls.Load(), cloudfront.calls.Load())
	}
}

func TestVerifierRoutingUsesExplicitCNAMEHints(t *testing.T) {
	heroku := &recordingVerifier{name: "Heroku"}
	github := &recordingVerifier{name: "GitHub Pages"}
	engine := &Engine{takeoverVerifiers: []Verifier{heroku, github}}
	analysis := &core.HostAnalysis{
		Host:           "app.example.com",
		Classification: "ORPHANED",
		DNS:            core.DNSRecordSet{CNAME: []string{"target.herokuapp.com"}},
	}

	engine.Run(context.Background(), analysis)

	if heroku.calls.Load() != 1 || github.calls.Load() != 0 {
		t.Fatalf("routed calls: heroku=%d github=%d", heroku.calls.Load(), github.calls.Load())
	}
}

func TestVerifierRoutingRejectsCNAMEFragmentCollisions(t *testing.T) {
	tests := []struct {
		name         string
		verifierName string
		cname        string
	}{
		{name: "GitHub sem fronteira", verifierName: "GitHub Pages", cname: "evilgithub.io"},
		{name: "GitHub como domínio pai falso", verifierName: "GitHub Pages", cname: "user.github.io.attacker.example"},
		{name: "Fastly sem fronteira", verifierName: "Fastly", cname: "evilfastly.net"},
		{name: "S3 como domínio pai falso", verifierName: "AWS S3", cname: "bucket.s3.amazonaws.com.attacker.example"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier := &recordingVerifier{name: test.verifierName}
			engine := &Engine{takeoverVerifiers: []Verifier{verifier}}
			analysis := &core.HostAnalysis{
				Host:           "target.example",
				Classification: "ORPHANED",
				DNS:            core.DNSRecordSet{CNAME: []string{test.cname}},
			}

			engine.Run(context.Background(), analysis)

			if got := verifier.calls.Load(); got != 0 {
				t.Fatalf("o CNAME colisor acionou o verificador %d vez(es)", got)
			}
		})
	}
}

func TestProviderTextMatchesOnlyExactNamesAndAliases(t *testing.T) {
	tests := []struct {
		name        string
		verifierKey string
		value       string
		want        bool
	}{
		{name: "nome exato", verifierKey: "githubpages", value: "GitHub Pages", want: true},
		{name: "alias legado explícito", verifierKey: "githubpages", value: "github_takeover_detection", want: true},
		{name: "identificador canônico", verifierKey: "awss3", value: "AWS/S3", want: true},
		{name: "prefixo hostil", verifierKey: "githubpages", value: "evilgithub", want: false},
		{name: "nome com prefixo extra", verifierKey: "githubpages", value: "notgithubpages", want: false},
		{name: "alias com sufixo extra", verifierKey: "githubpages", value: "github_takeover_detection_attacker", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := providerTextMatches(test.verifierKey, test.value); got != test.want {
				t.Fatalf("providerTextMatches(%q, %q) = %t; esperado %t", test.verifierKey, test.value, got, test.want)
			}
		})
	}
}

func TestCloudRoutingRequiresProviderDNSBoundary(t *testing.T) {
	for _, test := range []struct {
		name  string
		cname string
		want  int32
	}{
		{name: "S3 válido", cname: "bucket.s3.amazonaws.com.", want: 1},
		{name: "sufixo controlado por terceiro", cname: "bucket.s3.amazonaws.com.attacker.example", want: 0},
		{name: "fragmento colisor", cname: "evilamazonaws.com", want: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			verifier := &recordingVerifier{name: "AWS S3"}
			engine := &Engine{
				config:         Config{CheckCloud: true},
				cloudVerifiers: []Verifier{verifier},
			}
			analysis := &core.HostAnalysis{
				Host: "target.example",
				DNS:  core.DNSRecordSet{CNAME: []string{test.cname}},
			}

			engine.Run(context.Background(), analysis)

			if got := verifier.calls.Load(); got != test.want {
				t.Fatalf("chamadas do verificador = %d; esperado %d", got, test.want)
			}
		})
	}
}

func TestVerifierRoutingSkipsUnknownProviders(t *testing.T) {
	verifier := &recordingVerifier{name: "GitHub Pages"}
	engine := &Engine{takeoverVerifiers: []Verifier{verifier}}
	analysis := &core.HostAnalysis{Host: "unknown.example.com", Classification: "ORPHANED", DNS: core.DNSRecordSet{CNAME: []string{"unrelated.invalid"}}}

	engine.Run(context.Background(), analysis)

	if verifier.calls.Load() != 0 {
		t.Fatalf("unknown provider triggered %d active verifier calls", verifier.calls.Load())
	}
}

func TestCloudModuleRecordsItsEvaluationWithoutCandidate(t *testing.T) {
	engine := &Engine{config: Config{CheckCloud: true}}
	analysis := &core.HostAnalysis{Host: "host.example.com"}
	engine.Run(context.Background(), analysis)
	for _, vector := range analysis.TestedVectors {
		if vector == "CLOUD" {
			return
		}
	}
	t.Fatalf("o módulo de nuvem avaliado não foi registrado: %v", analysis.TestedVectors)
}
