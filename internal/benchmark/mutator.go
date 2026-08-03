package benchmark

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/evidence"
	"github.com/amchdd/subdomainabber/internal/presentation"
	"github.com/amchdd/subdomainabber/pkg/signatures"
)

type MutatorMetrics struct {
	Scenarios            int
	ProbesExecuted       int
	Rejected             int
	Differentials        int
	FingerprintsRevealed int
	TruePositives        int
	FalsePositives       int
	FalseNegatives       int
	ScenarioResults      []MutatorScenarioResult
}

type MutatorScenarioResult struct {
	Name       string
	Probe      string
	Revealed   bool
	ShouldFind bool
	Outcome    core.MutationOutcome
}

func (m MutatorMetrics) Precision() float64 {
	denominator := m.TruePositives + m.FalsePositives
	if denominator == 0 {
		return 100
	}
	return float64(m.TruePositives) * 100 / float64(denominator)
}

func (m MutatorMetrics) Recall() float64 {
	denominator := m.TruePositives + m.FalseNegatives
	if denominator == 0 {
		return 100
	}
	return float64(m.TruePositives) * 100 / float64(denominator)
}

type benchmarkRawTransport struct {
	mu        sync.Mutex
	responses []core.RawHTTPObservation
}

func (t *benchmarkRawTransport) Send(_ context.Context, _ core.MutationContext, _ []byte) core.RawHTTPObservation {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.responses) == 0 {
		return core.RawHTTPObservation{TransportError: "chamada inesperada"}
	}
	response := t.responses[0]
	t.responses = t.responses[1:]
	return response
}

type mutatorScenario struct {
	name       string
	probe      evidence.HTTPMutation
	provider   core.ProviderCandidate
	signatures []signatures.Fingerprint
	baseline   core.HTTPObservation
	responses  []core.RawHTTPObservation
	shouldFind bool
}

func RunMutatorBenchmark() MutatorMetrics {
	s3 := signatures.Fingerprint{Service: "AWS/S3", CNames: []string{"s3.amazonaws.com"}, Fingerprint: "The specified bucket does not exist", CheckType: "cname", Vulnerable: true, Status: "Vulnerable"}
	github := signatures.Fingerprint{Service: "GitHub Pages", CNames: []string{"github.io"}, Fingerprint: "There isn't a GitHub Pages site here.", CheckType: "cname", Vulnerable: true, Status: "Vulnerable"}
	awsCandidate := core.ProviderCandidate{ProviderID: "aws_s3", Service: "AWS/S3", CNAME: "bucket.s3.amazonaws.com"}
	githubCandidate := core.ProviderCandidate{ProviderID: "github_pages", Service: "GitHub Pages", CNAME: "owner.github.io"}
	blocked := raw(403, "Access denied")
	s3Missing := raw(404, s3.Fingerprint)
	githubMissing := raw(404, github.Fingerprint)

	scenarios := []mutatorScenario{
		{name: "Normalização de ponto final similar ao Nginx", probe: evidence.HostTrailingDotProbe{}, provider: awsCandidate, signatures: []signatures.Fingerprint{s3}, baseline: baseline(403, "Access denied"), responses: sequence(blocked, s3Missing, s3Missing, blocked), shouldFind: true},
		{name: "Separação por espaço no Host similar ao HAProxy", probe: evidence.HostWhitespaceProbe{}, provider: githubCandidate, signatures: []signatures.Fingerprint{github}, baseline: baseline(403, "Access denied"), responses: sequence(blocked, githubMissing, githubMissing, blocked), shouldFind: true},
		{name: "Normalização de porta explícita similar ao Envoy", probe: evidence.ExplicitPortProbe{}, provider: awsCandidate, signatures: []signatures.Fingerprint{s3}, baseline: baseline(403, "Access denied"), responses: sequence(blocked, s3Missing, s3Missing, blocked), shouldFind: true},
		{name: "Roteamento em forma absoluta similar ao Traefik", probe: evidence.AbsoluteFormProbe{}, provider: githubCandidate, signatures: []signatures.Fingerprint{github}, baseline: baseline(403, "Access denied"), responses: sequence(blocked, githubMissing, githubMissing, blocked), shouldFind: true},
		{name: "Rejeição de NUL similar ao Apache", probe: evidence.NullByteHostProbe{}, provider: awsCandidate, signatures: []signatures.Fingerprint{s3}, baseline: baseline(403, "Access denied"), responses: sequence(raw(400, "Bad request"), raw(400, "Bad request"), raw(400, "Bad request"), raw(400, "Bad request"))},
		{name: "Página de bloqueio personalizada e estável", probe: evidence.HostTrailingDotProbe{}, provider: awsCandidate, signatures: []signatures.Fingerprint{s3}, baseline: baseline(403, "Access denied"), responses: sequence(blocked, blocked, blocked, blocked)},
		{name: "Vazamento da aplicação de origem não reproduzível", probe: evidence.HostWhitespaceProbe{}, provider: awsCandidate, signatures: []signatures.Fingerprint{s3}, baseline: baseline(403, "Access denied"), responses: sequence(blocked, s3Missing, blocked, blocked)},
		{name: "Assinatura de outro provedor", probe: evidence.AbsoluteFormProbe{}, provider: awsCandidate, signatures: []signatures.Fingerprint{s3, github}, baseline: baseline(403, "Access denied"), responses: sequence(blocked, githubMissing, githubMissing, blocked)},
		{name: "Camada intermediária HTTP 200 não reconhecida", probe: evidence.HostTrailingDotProbe{}, provider: awsCandidate, signatures: []signatures.Fingerprint{s3}, baseline: baseline(200, "Please enable JavaScript"), responses: sequence(raw(200, "Please enable JavaScript"), s3Missing, s3Missing, raw(200, "Please enable JavaScript")), shouldFind: true},
		{name: "Camada intermediária HTTP 404 não reconhecida", probe: evidence.HostTrailingDotProbe{}, provider: awsCandidate, signatures: []signatures.Fingerprint{s3}, baseline: baseline(404, "Custom edge page"), responses: sequence(raw(404, "Custom edge page"), s3Missing, s3Missing, raw(404, "Custom edge page")), shouldFind: true},
		{name: "Camada intermediária HTTP 503 não reconhecida", probe: evidence.HostTrailingDotProbe{}, provider: awsCandidate, signatures: []signatures.Fingerprint{s3}, baseline: baseline(503, "Temporarily unavailable"), responses: sequence(raw(503, "Temporarily unavailable"), s3Missing, s3Missing, raw(503, "Temporarily unavailable")), shouldFind: true},
	}

	metrics := MutatorMetrics{Scenarios: len(scenarios)}
	for _, scenario := range scenarios {
		analysis := &core.HostAnalysis{Host: "target.example"}
		analysis.AddProviderCandidate(scenario.provider)
		analysis.SetHTTPObservation("http", scenario.baseline)
		collector := evidence.NewHTTPMutatorCollector(scenario.signatures, time.Second)
		collector.SetMutations([]evidence.HTTPMutation{scenario.probe})
		collector.SetTransport(&benchmarkRawTransport{responses: append([]core.RawHTTPObservation(nil), scenario.responses...)})
		_ = collector.Collect(context.Background(), analysis)
		revealed := hasBenchmarkEvidence(analysis, "HTTP_MUTATION_REVEALED_PROVIDER_FINGERPRINT")
		result := MutatorScenarioResult{Name: scenario.name, Probe: scenario.probe.Name(), Revealed: revealed, ShouldFind: scenario.shouldFind}
		if len(analysis.MutationResults) > 0 {
			result.Outcome = analysis.MutationResults[0].Outcome
			metrics.ProbesExecuted += len(analysis.MutationResults)
			for _, mutation := range analysis.MutationResults {
				switch mutation.Outcome {
				case core.MutationRejected, core.MutationTransportFailure:
					metrics.Rejected++
				case core.MutationReproducibleDifferential, core.MutationRevealedProviderFingerprint:
					metrics.Differentials++
				}
			}
		}
		if revealed {
			metrics.FingerprintsRevealed++
		}
		if scenario.shouldFind && revealed {
			metrics.TruePositives++
		}
		if scenario.shouldFind && !revealed {
			metrics.FalseNegatives++
		}
		if !scenario.shouldFind && revealed {
			metrics.FalsePositives++
		}
		metrics.ScenarioResults = append(metrics.ScenarioResults, result)
	}
	return metrics
}

func PrintMutatorBenchmark(metrics MutatorMetrics) {
	fmt.Println("\nBenchmark controlado do HTTP Mutator")
	fmt.Println("====================================")
	for _, scenario := range metrics.ScenarioResults {
		fmt.Printf("%-52s %-26s resultado=%-36s revelado=%s esperado=%s\n",
			scenario.Name,
			scenario.Probe,
			presentation.Value(string(scenario.Outcome)),
			yesNo(scenario.Revealed),
			yesNo(scenario.ShouldFind),
		)
	}
	fmt.Printf("\nCenários:                   %d\n", metrics.Scenarios)
	fmt.Printf("Sondas executadas:          %d\n", metrics.ProbesExecuted)
	fmt.Printf("Rejeitadas/transporte:      %d\n", metrics.Rejected)
	fmt.Printf("Diferenciais:               %d\n", metrics.Differentials)
	fmt.Printf("Assinaturas reveladas:      %d\n", metrics.FingerprintsRevealed)
	fmt.Printf("Falsos positivos:           %d\n", metrics.FalsePositives)
	fmt.Printf("Falsos negativos:           %d\n", metrics.FalseNegatives)
	fmt.Printf("Precisão:                   %.2f%%\n", metrics.Precision())
	fmt.Printf("Sensibilidade:              %.2f%%\n", metrics.Recall())
	fmt.Println("\nNota: os nomes das pilhas descrevem comportamentos controlados de análise sintática, não alegações de vulnerabilidade dos fornecedores.")
}

func yesNo(value bool) string {
	if value {
		return "sim"
	}
	return "não"
}

func baseline(status int, body string) core.HTTPObservation {
	return core.HTTPObservation{Scheme: "http", StatusCode: status, Headers: http.Header{"Server": {"controlled-edge"}}, Body: []byte(body), NormalizedBody: []byte(body), Complete: true, Server: "controlled-edge"}
}
func raw(status int, body string) core.RawHTTPObservation {
	return core.RawHTTPObservation{StatusCode: status, Body: []byte(body), Complete: true}
}
func sequence(values ...core.RawHTTPObservation) []core.RawHTTPObservation { return values }
func hasBenchmarkEvidence(analysis *core.HostAnalysis, evidenceType string) bool {
	for _, item := range analysis.Evidences {
		if item.Type == evidenceType {
			return true
		}
	}
	return false
}
