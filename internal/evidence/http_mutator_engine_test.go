package evidence

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amchdd/subdomainabber/internal/classification"
	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/dns"
	"github.com/amchdd/subdomainabber/pkg/signatures"
)

type scriptedRawTransport struct {
	mu        sync.Mutex
	responses []core.RawHTTPObservation
	payloads  [][]byte
	contexts  []core.MutationContext
}

func TestHTTPMutatorRecordsModuleEvaluationWithoutEligibleCandidate(t *testing.T) {
	collector := NewHTTPMutatorCollector(nil, time.Second)
	analysis := &core.HostAnalysis{Host: "host.example.com"}
	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if !containsTestedVector(analysis.TestedVectors, "HTTP_MUTATOR") {
		t.Fatalf("o módulo avaliado não foi registrado: %v", analysis.TestedVectors)
	}
}

func (transport *scriptedRawTransport) Send(_ context.Context, mutationContext core.MutationContext, payload []byte) core.RawHTTPObservation {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.payloads = append(transport.payloads, append([]byte(nil), payload...))
	transport.contexts = append(transport.contexts, mutationContext)
	if len(transport.responses) == 0 {
		return core.RawHTTPObservation{TransportError: "unexpected transport call"}
	}
	response := transport.responses[0]
	transport.responses = transport.responses[1:]
	return response
}

func TestRemainingBaselineFingerprintCannotBeRevealedAgain(t *testing.T) {
	fingerprint := []byte("The specified bucket does not exist")
	analysis := mutationAnalysis(t, true, fingerprint)
	transport := successMutationTransport(string(fingerprint))
	collector := testMutator(transport, awsSignature())
	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if _, found := findEvidence(analysis, "HTTP_MUTATION_REVEALED_PROVIDER_FINGERPRINT"); found {
		t.Fatal("fingerprint already present in initial baseline was described as revealed")
	}
}

func TestRemainingFingerprintConfirmationEnforcesBaselineInvariantInternally(t *testing.T) {
	ctx := testMutationContext("example.com")
	ctx.Baseline = newHTTPObservation("http", 403, nil, []byte("The specified bucket does not exist"), true, 0, "", "")
	response := core.RawHTTPObservation{StatusCode: 404, Body: []byte("The specified bucket does not exist"), Complete: true}
	control := core.RawHTTPObservation{StatusCode: 403, Body: []byte("Access denied"), Complete: true}
	collector := NewHTTPMutatorCollector([]signatures.Fingerprint{awsSignature()}, time.Second)
	if _, confirmed := collector.confirmedProviderFingerprint(ctx, "HostWhitespaceProbe", response, response, control, control); confirmed {
		t.Fatal("confirmation helper ignored fingerprint in initial baseline")
	}
}

func TestRemainingFingerprintConfirmationEnforcesBothRawControlInvariantsInternally(t *testing.T) {
	ctx := testMutationContext("example.com")
	fingerprint := core.RawHTTPObservation{StatusCode: 404, Body: []byte("The specified bucket does not exist"), Complete: true}
	plainControl := core.RawHTTPObservation{StatusCode: 403, Body: []byte("Access denied"), Complete: true}
	collector := NewHTTPMutatorCollector([]signatures.Fingerprint{awsSignature()}, time.Second)

	tests := []struct {
		name          string
		controlBefore core.RawHTTPObservation
		controlAfter  core.RawHTTPObservation
	}{
		{name: "control before", controlBefore: fingerprint, controlAfter: plainControl},
		{name: "control after", controlBefore: plainControl, controlAfter: fingerprint},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, confirmed := collector.confirmedProviderFingerprint(ctx, "HostWhitespaceProbe", fingerprint, fingerprint, test.controlBefore, test.controlAfter); confirmed {
				t.Fatal("confirmation helper ignored provider fingerprint in a raw control")
			}
		})
	}
}

func TestRemainingControlAfterFingerprintCannotBeAttributedToMutation(t *testing.T) {
	signature := awsSignature()
	signature.Fingerprint = "providerfingerprint1234"
	analysis := mutationAnalysis(t, true, []byte("Access denied"))
	control := core.RawHTTPObservation{StatusCode: 403, Body: []byte("request-id: abcdefgh12345678"), Complete: true}
	mutation := core.RawHTTPObservation{StatusCode: 404, Body: []byte("request-id: providerfingerprint1234"), Complete: true}
	controlAfter := core.RawHTTPObservation{StatusCode: 403, Body: []byte("request-id: providerfingerprint1234"), Complete: true}
	transport := &scriptedRawTransport{responses: []core.RawHTTPObservation{control, mutation, mutation, controlAfter}}
	collector := testMutator(transport, signature)

	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if _, found := findEvidence(analysis, "HTTP_MUTATION_REVEALED_PROVIDER_FINGERPRINT"); found {
		t.Fatal("fingerprint present in the trailing raw control was attributed to the mutation")
	}
	if _, found := findEvidence(analysis, "HTTP_MUTATION_DIFFERENTIAL"); found {
		t.Fatal("mutation differential was emitted even though the trailing control contained the same provider fingerprint")
	}
	if _, found := findEvidence(analysis, "HTTP_RAW_CONTROL_DIFFERENTIAL"); !found {
		t.Fatal("trailing raw control fingerprint was not retained as neutral control evidence")
	}
}

func TestRemainingDefaultMutationsExcludeFraming(t *testing.T) {
	for _, mutation := range DefaultHTTPMutations() {
		if mutation.Name() == "CLTEProbe" || mutation.Name() == "TECLProbe" {
			t.Fatalf("high-risk framing probe present in defaults: %s", mutation.Name())
		}
	}
}

func TestRemainingHTTPSReceivesIndependentProbeBudget(t *testing.T) {
	analysis := mutationAnalysis(t, true, []byte("Access denied"))
	analysis.SetHTTPObservation("https", newHTTPObservation("https", 403, nil, []byte("Access denied"), true, 0, "", ""))
	response := core.RawHTTPObservation{StatusCode: 403, Body: []byte("Access denied"), Complete: true}
	responses := make([]core.RawHTTPObservation, 14*4)
	for i := range responses {
		responses[i] = response
	}
	transport := &scriptedRawTransport{responses: responses}
	collector := NewHTTPMutatorCollector([]signatures.Fingerprint{awsSignature()}, time.Second)
	collector.SetTransport(transport)
	collector.SetLimits(7, time.Second)
	collector.SetMutations([]HTTPMutation{HostWhitespaceProbe{}, HostWhitespaceProbe{}, HostWhitespaceProbe{}, HostWhitespaceProbe{}, HostWhitespaceProbe{}, HostWhitespaceProbe{}, HostWhitespaceProbe{}})
	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if len(analysis.MutationResults) != 14 {
		t.Fatalf("results = %d, want seven per scheme", len(analysis.MutationResults))
	}
	if len(transport.contexts) == 0 || transport.contexts[0].Scheme != "https" {
		t.Fatalf("first scheme = %q, want https priority", transport.contexts[0].Scheme)
	}
}

func TestRemainingGenericFingerprintIsNeutralInMutator(t *testing.T) {
	signature := signatures.Fingerprint{Service: "Generic Provider", CNames: []string{"provider.example"}, Fingerprint: "404 Not Found", CheckType: "cname", Vulnerable: true, Status: "Vulnerable"}
	analysis := &core.HostAnalysis{Host: "site.example.com"}
	analysis.AddProviderCandidate(core.ProviderCandidate{ProviderID: "generic_provider", Service: "Generic Provider", CNAME: "site.provider.example"})
	analysis.AddEvidence(core.Evidence{Type: "CNAME_PROVIDER_MATCH", Source: "Generic Provider", Metadata: map[string]string{"provider_id": "generic_provider", "matched_cname": "site.provider.example"}})
	analysis.SetHTTPObservation("http", newHTTPObservation("http", 403, nil, []byte("Access denied"), true, 0, "", ""))
	transport := successMutationTransport("404 Not Found")
	collector := testMutator(transport, signature)
	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if _, found := findEvidence(analysis, "HTTP_MUTATION_REVEALED_PROVIDER_FINGERPRINT"); found {
		t.Fatal("generic fingerprint became classifiable evidence")
	}
	if _, found := findEvidence(analysis, "HTTP_MUTATION_FINGERPRINT_REVIEW"); !found {
		t.Fatal("generic fingerprint was not retained as neutral review evidence")
	}
	if got := classification.Classify(analysis); got != classification.LevelUnknown {
		t.Fatalf("classification = %s", got)
	}
}

func (transport *scriptedRawTransport) callCount() int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return len(transport.payloads)
}

type buildErrorMutation struct{}

func (buildErrorMutation) Name() string                            { return "BuildErrorProbe" }
func (buildErrorMutation) Description() string                     { return "build error" }
func (buildErrorMutation) Applicability(core.MutationContext) bool { return true }
func (buildErrorMutation) BuildControl(core.MutationContext) ([]byte, error) {
	return nil, errors.New("build failed")
}
func (buildErrorMutation) BuildMutation(core.MutationContext) ([]byte, error) {
	return nil, errors.New("build failed")
}

func TestHTTPMutatorRequiresStoredBaseline(t *testing.T) {
	analysis := mutationAnalysis(t, false, []byte("Access denied"))
	transport := &scriptedRawTransport{}
	collector := testMutator(transport, awsSignature())

	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if transport.callCount() != 0 || len(analysis.MutationResults) != 0 {
		t.Fatalf("mutator executed without baseline: calls=%d results=%d", transport.callCount(), len(analysis.MutationResults))
	}
}

func TestHTTPMutatorIgnoresNonCNAMEAndIncompatibleCandidates(t *testing.T) {
	tests := []core.ProviderCandidate{
		{ProviderID: "aws", Service: "AWS", Vector: "A", Resource: "192.0.2.10"},
		{ProviderID: "aws_s3", Service: "AWS/S3", Vector: "CNAME", CNAME: "unrelated.example.net"},
	}
	for _, candidate := range tests {
		analysis := &core.HostAnalysis{Host: "assets.example.com"}
		analysis.AddProviderCandidate(candidate)
		analysis.SetHTTPObservation("https", newHTTPObservation("https", 403, nil, []byte("Access denied"), true, 0, "", ""))
		transport := &scriptedRawTransport{}
		collector := testMutator(transport, awsSignature())

		if err := collector.Collect(context.Background(), analysis); err != nil {
			t.Fatal(err)
		}
		if transport.callCount() != 0 || len(analysis.MutationResults) != 0 {
			t.Fatalf("candidate %#v triggered mutator: calls=%d results=%d", candidate, transport.callCount(), len(analysis.MutationResults))
		}
	}
}

func TestHTTPMutatorConfirmsProviderBoundFingerprint(t *testing.T) {
	analysis := mutationAnalysis(t, true, []byte("Access denied"))
	transport := successMutationTransport("The specified bucket does not exist")
	collector := testMutator(transport, awsSignature())

	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	evidence, found := findEvidence(analysis, "HTTP_MUTATION_REVEALED_PROVIDER_FINGERPRINT")
	if !found {
		t.Fatalf("provider fingerprint evidence not emitted: %#v", analysis.Evidences)
	}
	if evidence.Source != "AWS/S3" || evidence.Metadata["confirmations"] != "2" || evidence.Metadata["matched_fingerprint"] != "The specified bucket does not exist" || evidence.Metadata["rule_id"] == "" {
		t.Fatalf("unexpected revealed evidence: %#v", evidence)
	}
	if _, legacy := findEvidence(analysis, "HTTP_BODY_MATCH"); legacy {
		t.Fatal("mutator emitted legacy HTTP_BODY_MATCH")
	}
	if len(analysis.MutationResults) != 1 || analysis.MutationResults[0].Outcome != core.MutationRevealedProviderFingerprint {
		t.Fatalf("unexpected mutation result: %#v", analysis.MutationResults)
	}
}

func TestHTTPMutatorConfirmsReproducible403To200Fingerprint(t *testing.T) {
	analysis := mutationAnalysis(t, true, []byte("Access denied"))
	transport := &scriptedRawTransport{responses: []core.RawHTTPObservation{
		{StatusCode: 403, Headers: map[string][]string{"Server": {"cloudflare"}}, Body: []byte("Access denied"), Complete: true},
		{StatusCode: 200, Body: []byte("The specified bucket does not exist"), Complete: true},
		{StatusCode: 200, Body: []byte("The specified bucket does not exist"), Complete: true},
		{StatusCode: 403, Headers: map[string][]string{"Server": {"cloudflare"}}, Body: []byte("Access denied"), Complete: true},
	}}
	collector := testMutator(transport, awsSignature())

	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	evidence, found := findEvidence(analysis, "HTTP_MUTATION_REVEALED_PROVIDER_FINGERPRINT")
	if !found || evidence.Metadata["mutated_status"] != "200" {
		t.Fatalf("reproducible 403 -> 200 provider fingerprint was not confirmed: %#v", analysis.Evidences)
	}
}

func TestHTTPMutatorRejectsUnboundAndUnconfirmedFingerprints(t *testing.T) {
	tests := []struct {
		name         string
		baselineBody string
		mutatedBody  string
		signatures   []signatures.Fingerprint
	}{
		{name: "different provider", baselineBody: "Access denied", mutatedBody: "There isn't a GitHub Pages site here.", signatures: []signatures.Fingerprint{awsSignature(), githubSignature()}},
		{name: "generic 404", baselineBody: "Access denied", mutatedBody: "404 Not Found", signatures: []signatures.Fingerprint{awsSignature()}},
		{name: "empty fingerprint", baselineBody: "Access denied", mutatedBody: "anything", signatures: []signatures.Fingerprint{{Service: "AWS/S3", CNames: []string{"s3.amazonaws.com"}, CheckType: "cname"}}},
		{name: "dynamic content only", baselineBody: "Access denied", mutatedBody: "request-id: abcdefgh12345678", signatures: []signatures.Fingerprint{awsSignature()}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := mutationAnalysis(t, true, []byte(tt.baselineBody))
			transport := successMutationTransport(tt.mutatedBody)
			collector := testMutator(transport, tt.signatures...)
			if err := collector.Collect(context.Background(), analysis); err != nil {
				t.Fatalf("Collect: %v", err)
			}
			if evidence, found := findEvidence(analysis, "HTTP_MUTATION_REVEALED_PROVIDER_FINGERPRINT"); found {
				t.Fatalf("unexpected provider evidence: %#v", evidence)
			}
		})
	}
}

func TestFramingProbeDoesNotTakeCreditWhenNormalPOSTRevealsFingerprint(t *testing.T) {
	fingerprint := []byte("The specified bucket does not exist")
	analysis := mutationAnalysis(t, true, []byte("Access denied"))
	transport := &scriptedRawTransport{responses: []core.RawHTTPObservation{
		{StatusCode: 404, Body: fingerprint, Complete: true},
		{StatusCode: 404, Body: fingerprint, Complete: true},
		{StatusCode: 404, Body: fingerprint, Complete: true},
		{StatusCode: 404, Body: fingerprint, Complete: true},
	}}
	collector := testFramingCollector(t, "example.com", transport)
	collector.SetMutations([]HTTPMutation{CLTEProbe{}})
	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if _, found := findEvidence(analysis, "HTTP_MUTATION_REVEALED_PROVIDER_FINGERPRINT"); found {
		t.Fatal("CL.TE received credit for a fingerprint already present in normal POST")
	}
	if _, found := findEvidence(analysis, "CLTE_MUTATION_DIFFERENTIAL"); found {
		t.Fatal("CL.TE differential emitted without a framing difference")
	}
	if got := analysis.MutationResults[0].Outcome; got != core.MutationFramingNoDifference {
		t.Fatalf("outcome = %s", got)
	}
}

func TestPlan3FramingOutcomeMatrix(t *testing.T) {
	control := core.RawHTTPObservation{StatusCode: 403, Body: []byte("Access denied"), Complete: true}
	tests := []struct {
		name        string
		mutation    core.RawHTTPObservation
		want        core.MutationOutcome
		wantNeutral bool
	}{
		{name: "both 403", mutation: control, want: core.MutationFramingNoDifference},
		{name: "mutation 400", mutation: core.RawHTTPObservation{StatusCode: 400, Body: []byte("bad request"), Complete: true}, want: core.MutationFramingRejected},
		{name: "mutation timeout", mutation: core.RawHTTPObservation{TimedOut: true, TransportError: "timeout"}, want: core.MutationFramingTransportFailure},
		{name: "different without fingerprint", mutation: core.RawHTTPObservation{StatusCode: 200, Body: []byte("different response"), Complete: true}, want: core.MutationFramingDifferential, wantNeutral: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := mutationAnalysis(t, true, control.Body)
			transport := &scriptedRawTransport{responses: []core.RawHTTPObservation{control, tt.mutation, tt.mutation, control}}
			collector := testFramingCollector(t, "example.com", transport)
			collector.SetMutations([]HTTPMutation{CLTEProbe{}})
			if err := collector.Collect(context.Background(), analysis); err != nil {
				t.Fatal(err)
			}
			if got := analysis.MutationResults[0].Outcome; got != tt.want {
				t.Fatalf("outcome = %s, want %s", got, tt.want)
			}
			_, neutral := findEvidence(analysis, "FRAMING_DIFFERENTIAL")
			if neutral != tt.wantNeutral {
				t.Fatalf("neutral differential = %v, want %v", neutral, tt.wantNeutral)
			}
			if _, found := findEvidence(analysis, "HTTP_MUTATION_REVEALED_PROVIDER_FINGERPRINT"); found {
				t.Fatal("unexpected provider fingerprint")
			}
		})
	}
}

func TestProbeBuildErrorDoesNotInterruptOtherProbes(t *testing.T) {
	analysis := mutationAnalysis(t, true, []byte("Access denied"))
	transport := successMutationTransport("The specified bucket does not exist")
	collector := NewHTTPMutatorCollector([]signatures.Fingerprint{awsSignature()}, 0)
	collector.SetTransport(transport)
	collector.SetMutations([]HTTPMutation{buildErrorMutation{}, HostWhitespaceProbe{}})

	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(analysis.MutationResults) != 2 {
		t.Fatalf("expected results for both probes, got %#v", analysis.MutationResults)
	}
	if analysis.MutationResults[0].Outcome != core.MutationRejected || analysis.MutationResults[1].Outcome != core.MutationRevealedProviderFingerprint {
		t.Fatalf("probe error interrupted later probe: %#v", analysis.MutationResults)
	}
}

func TestLocalPipelineRevealsProviderFingerprintAfterBaseline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	done := make(chan struct{})
	defer close(done)
	go serveMutationPipeline(listener, done)

	signature := awsSignature()
	analysis := &core.HostAnalysis{
		Host: listener.Addr().String(),
		DNS: core.DNSRecordSet{
			A:     []string{"127.0.0.1"},
			CNAME: []string{"bucket.s3.amazonaws.com"},
		},
	}
	baselineCollector := NewHTTPCollector([]signatures.Fingerprint{signature}, 200*time.Millisecond, "", false, "test-agent", false)
	mutator := NewHTTPMutatorCollector([]signatures.Fingerprint{signature}, 300*time.Millisecond)
	mutator.SetMutations([]HTTPMutation{HostWhitespaceProbe{}})
	registry := NewRegistry([]Collector{
		NewCNAMECollector((*dns.Resolver)(nil), []signatures.Fingerprint{signature}),
		baselineCollector,
		mutator,
	})

	if err := registry.Run(context.Background(), analysis); err != nil {
		t.Fatalf("pipeline Run: %v", err)
	}
	baseline, exists := analysis.HTTPObservation("http")
	if !exists || !baseline.Complete || baseline.StatusCode != 403 {
		t.Fatalf("baseline was not stored before mutation: %#v", baseline)
	}
	if _, found := findEvidence(analysis, "HTTP_MUTATION_REVEALED_PROVIDER_FINGERPRINT"); !found {
		t.Fatalf("pipeline did not reveal provider fingerprint: %#v", analysis.Evidences)
	}
	classification.Process(analysis)
	if analysis.Classification != classification.LevelLikelyTakeoverable {
		t.Fatalf("classification = %s, want %s", analysis.Classification, classification.LevelLikelyTakeoverable)
	}
}

func serveMutationPipeline(listener net.Listener, done <-chan struct{}) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
			reader := bufio.NewReader(conn)
			requestLine, err := reader.ReadString('\n')
			if err != nil || !strings.HasPrefix(requestLine, "GET ") {
				return
			}
			mutated := false
			for {
				line, readErr := reader.ReadString('\n')
				if readErr != nil {
					return
				}
				if strings.HasPrefix(line, "Host:  ") {
					mutated = true
				}
				if line == "\r\n" {
					break
				}
			}
			if mutated {
				body := "The specified bucket does not exist"
				_, _ = fmt.Fprintf(conn, "HTTP/1.1 404 Not Found\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
				return
			}
			body := "Access denied"
			_, _ = fmt.Fprintf(conn, "HTTP/1.1 403 Forbidden\r\nServer: cloudflare\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
		}(conn)
		select {
		case <-done:
			return
		default:
		}
	}
}

func testMutator(transport HTTPRawTransport, sigs ...signatures.Fingerprint) *HTTPMutatorCollector {
	collector := NewHTTPMutatorCollector(sigs, 0)
	collector.SetTransport(transport)
	collector.SetMutations([]HTTPMutation{HostWhitespaceProbe{}})
	return collector
}

func mutationAnalysis(t *testing.T, withBaseline bool, baselineBody []byte) *core.HostAnalysis {
	t.Helper()
	analysis := &core.HostAnalysis{Host: "example.com"}
	analysis.AddProviderCandidate(core.ProviderCandidate{
		ProviderID: "aws_s3",
		Service:    "AWS/S3",
		CNAME:      "bucket.s3.amazonaws.com",
	})
	if withBaseline {
		analysis.SetHTTPObservation("http", newHTTPObservation("http", 403, http.Header{"Server": []string{"cloudflare"}}, baselineBody, true, 0, "", ""))
	}
	return analysis
}

func successMutationTransport(mutatedBody string) *scriptedRawTransport {
	return &scriptedRawTransport{responses: []core.RawHTTPObservation{
		{StatusCode: 403, Headers: map[string][]string{"Server": {"cloudflare"}}, Body: []byte("Access denied"), Complete: true},
		{StatusCode: 404, Body: []byte(mutatedBody), Complete: true},
		{StatusCode: 404, Body: []byte(mutatedBody), Complete: true},
		{StatusCode: 403, Headers: map[string][]string{"Server": {"cloudflare"}}, Body: []byte("Access denied"), Complete: true},
	}}
}

func awsSignature() signatures.Fingerprint {
	return signatures.Fingerprint{
		Service:     "AWS/S3",
		CNames:      []string{"s3.amazonaws.com"},
		Fingerprint: "The specified bucket does not exist",
		CheckType:   "cname",
		Vulnerable:  true,
		Status:      "Vulnerable",
	}
}

func githubSignature() signatures.Fingerprint {
	return signatures.Fingerprint{
		Service:     "GitHub Pages",
		CNames:      []string{"github.io"},
		Fingerprint: "There isn't a GitHub Pages site here.",
		CheckType:   "cname",
		Vulnerable:  true,
		Status:      "Vulnerable",
	}
}

func findEvidence(analysis *core.HostAnalysis, evidenceType string) (core.Evidence, bool) {
	for _, evidence := range analysis.Evidences {
		if evidence.Type == evidenceType {
			return evidence, true
		}
	}
	return core.Evidence{}, false
}
