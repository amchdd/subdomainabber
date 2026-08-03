package benchmark

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/dns"
	"github.com/amchdd/subdomainabber/internal/evidence"
	"github.com/amchdd/subdomainabber/internal/storage"
	"github.com/amchdd/subdomainabber/internal/verifiers"
	"github.com/amchdd/subdomainabber/internal/verify"
	"github.com/amchdd/subdomainabber/pkg/signatures"
)

func RunL1Synthetic() bool {
	fmt.Println("Iniciando benchmark L1 de classificação sintética...")

	mock := NewMockServer()
	if err := mock.Start(); err != nil {
		fmt.Printf("Falha ao iniciar o servidor simulado: %v\n", err)
		return false
	}
	defer mock.Stop()

	// Configura os cenários sintéticos.
	setupL1Scenarios(mock)

	// Usa o servidor DNS local do benchmark.
	res := dns.New([]string{"127.0.0.1:53530"})

	// Carrega as assinaturas usadas pelo classificador.
	allSignatures := signatures.MergeSignatures(signatures.BuiltinNSSignatures())
	embeddedSigs, _ := signatures.LoadEmbedded()

	// A regra original do GitHub é rejeitada intencionalmente porque seu CNAME
	// embutido está vazio. A suíte sintética fornece uma regra válida explícita.
	embeddedSigs = append(embeddedSigs, signatures.Fingerprint{
		Service: "GitHub Pages", CNames: []string{"github.io"},
		Fingerprint: "There isn't a GitHub Pages site here.", Vulnerable: true,
		Status: "Vulnerable", CheckType: "cname", Confidence: 80,
	})

	allSignatures = append(allSignatures, embeddedSigs...)

	cnameCollector := evidence.NewCNAMECollector(res, allSignatures)
	nsCollector := evidence.NewNSCollector(res, allSignatures)
	mxCollector := evidence.NewMXCollector(res, allSignatures)
	txtCollector := evidence.NewTXTCollector(allSignatures)
	srvCollector := evidence.NewSRVCollector(res, allSignatures)
	// Os coletores locais usam um tempo limite curto para agilizar o benchmark.
	tlsCollector := evidence.NewTLSCollector(allSignatures, 2)
	tlsCollector.SetDialer(mock.TLSDialer())
	ipCollector := evidence.NewIPCollector(res, allSignatures)
	httpCollector := evidence.NewHTTPCollector(allSignatures, 3*time.Second, "", false, "", false)
	httpCollector.SetTransport(mock.RoundTripper())

	registry := evidence.NewRegistry([]evidence.Collector{
		cnameCollector, nsCollector, mxCollector, txtCollector, srvCollector, tlsCollector, ipCollector, httpCollector,
	})

	testClient := &http.Client{
		Timeout:   2 * time.Second,
		Transport: mock.RoundTripper(),
	}

	verifierEngine := verifiers.NewEngine(verifiers.Config{Client: testClient})
	db, _ := storage.New(":memory:")

	engine := verify.NewEngine(res, registry, verifierEngine, db)

	// Define a classificação de referência de cada caso.
	testCases := []TestCase{
		{Host: "gh-takeover.synthetic", Classification: ExpectedConfirmed, Provider: "GitHub Pages"},
		{Host: "aws-takeover.synthetic", Classification: ExpectedLikely, Provider: "AWS S3"},
		{Host: "healthy.synthetic", Classification: ExpectedHealthy},
		{Host: "ns-orphaned.synthetic", Classification: ExpectedDelegationBroken},
	}

	matrix := &Matrix{TotalRuns: len(testCases)}

	for _, tc := range testCases {
		hist := &core.HostAnalysis{Host: tc.Host}
		result, err := engine.Verify(context.Background(), hist)
		if err != nil {
			fmt.Printf("Erro ao avaliar %s: %v\n", tc.Host, err)
			continue
		}

		class := result.NewClassification

		if class == string(tc.Classification) {
			if isTakeoverSignal(string(tc.Classification)) {
				matrix.TakeoverTP++
			} else {
				matrix.TakeoverTN++
			}
		} else {
			expectedTakeover := isTakeoverSignal(string(tc.Classification))
			actualTakeover := isTakeoverSignal(class)
			matrix.FailedCases = append(matrix.FailedCases, fmt.Sprintf("%s (esperado: %s, obtido: %s)", tc.Host, tc.Classification, class))
			if expectedTakeover && !actualTakeover {
				matrix.TakeoverFN++
				fmt.Printf("Falso negativo em %s. Evidências:\n", tc.Host)
				for _, ev := range result.NewAnalysis.Evidences {
					fmt.Printf("   - %s: %s\n", ev.Type, ev.Description)
				}
			} else if !expectedTakeover && actualTakeover {
				matrix.TakeoverFP++
			} else if expectedTakeover && actualTakeover {
				matrix.TakeoverTP++
			} else {
				matrix.TakeoverTN++
			}
		}
	}

	matrix.Print()
	return len(matrix.FailedCases) == 0
}

func setupL1Scenarios(mock *MockServer) {
	// GitHub Pages pendente.
	mock.SetA("gh-takeover.synthetic.", "127.0.0.1")
	mock.SetCNAME("gh-takeover.synthetic.", "github.io.")
	mock.SetHTTP("gh-takeover.synthetic", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte("There isn't a GitHub Pages site here."))
	})
	mock.SetTLS("gh-takeover.synthetic", "gh-takeover.synthetic", "Mock CA", false)

	// Amazon S3 pendente.
	mock.SetA("aws-takeover.synthetic.", "127.0.0.1")
	mock.SetCNAME("aws-takeover.synthetic.", "my-bucket.s3.amazonaws.com.")
	mock.SetHTTP("aws-takeover.synthetic", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte("The specified bucket does not exist"))
	})
	mock.SetTLS("aws-takeover.synthetic", "aws-takeover.synthetic", "Mock CA", false)

	// Domínio saudável.
	mock.SetA("healthy.synthetic.", "1.1.1.1")
	mock.SetHTTP("healthy.synthetic", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("Welcome to my site"))
	})
	mock.SetTLS("healthy.synthetic", "healthy.synthetic", "Mock CA", false)

	// Falha de delegação NS, sem prova de takeover.
	mock.SetNS("ns-orphaned.synthetic.", "awsdns-12.com.")
	mock.SetNXDOMAIN("awsdns-12.com.")
}
