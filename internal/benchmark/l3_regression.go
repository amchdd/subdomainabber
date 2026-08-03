package benchmark

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/dns"
	"github.com/amchdd/subdomainabber/internal/evidence"
	"github.com/amchdd/subdomainabber/internal/storage"
	"github.com/amchdd/subdomainabber/internal/verifiers"
	"github.com/amchdd/subdomainabber/internal/verify"
	"github.com/amchdd/subdomainabber/pkg/signatures"
)

func RunL3Regression(datasetPath string) bool {
	fmt.Println("Iniciando benchmark L3 de regressão...")

	matrix := &Matrix{}

	allSignatures := signatures.MergeSignatures(signatures.BuiltinNSSignatures())
	embeddedSigs, _ := signatures.LoadEmbedded()

	// Adiciona a Heroku ao cenário quando ela não estiver no catálogo carregado.
	embeddedSigs = append(embeddedSigs, signatures.Fingerprint{
		Service:         "Heroku",
		CNames:          []string{"herokuapp.com", "heroku.com"},
		TLSFingerprints: []string{"herokuapp.com", "heroku.com"},
	})

	allSignatures = append(allSignatures, embeddedSigs...)

	// Percorre os arquivos JSON do conjunto de dados.
	var testCases []TestCase
	err := filepath.Walk(datasetPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".json" {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			var entry TestCase
			if err := json.Unmarshal(data, &entry); err != nil {
				return nil
			}
			testCases = append(testCases, entry)
		}
		return nil
	})

	if err != nil {
		fmt.Printf("Erro ao ler o conjunto de dados: %v\n", err)
		return false
	}

	if len(testCases) == 0 {
		fmt.Println("Nenhum caso de teste L3 encontrado no diretório", datasetPath)
		return false
	}

	for _, tc := range testCases {
		matrix.TotalRuns++

		// Configura o servidor simulado para o caso atual.
		mock := NewMockServer()
		if tc.Mock != nil {
			if tc.Mock.DNS != nil {
				if tc.Mock.DNS.NXDOMAIN {
					mock.SetNXDOMAIN(tc.Host)
				} else {
					for _, a := range tc.Mock.DNS.A {
						mock.SetA(tc.Host, a)
					}
					for _, aaaa := range tc.Mock.DNS.AAAA {
						mock.SetAAAA(tc.Host, aaaa)
					}
					for _, cname := range tc.Mock.DNS.CNAME {
						mock.SetCNAME(tc.Host, cname)
					}
					for _, ns := range tc.Mock.DNS.NS {
						mock.SetNS(tc.Host, ns)
					}
					for _, mx := range tc.Mock.DNS.MX {
						mock.SetMX(tc.Host, mx)
					}
					// Mantém o conteúdo TXT literal.
					for _, txt := range tc.Mock.DNS.TXT {
						mock.SetTXT(tc.Host, txt)
					}
				}
			}

			if tc.Mock.HTTP != nil {
				mock.SetHTTP(tc.Host, func(w http.ResponseWriter, r *http.Request) {
					for k, v := range tc.Mock.HTTP.Headers {
						w.Header().Set(k, v)
					}
					w.WriteHeader(tc.Mock.HTTP.Status)
					w.Write([]byte(tc.Mock.HTTP.Body))
				})
			}

			if tc.Mock.TLS != nil {
				mock.SetTLS(tc.Host, tc.Mock.TLS.Subject, tc.Mock.TLS.Issuer, tc.Mock.TLS.Expired)
			}
		}

		if err := mock.Start(); err != nil {
			matrix.FailedCases = append(matrix.FailedCases, fmt.Sprintf("%s (falha ao iniciar o simulador: %v)", tc.Host, err))
			continue
		}

		res := dns.New([]string{"127.0.0.1:53530"})

		cnameCollector := evidence.NewCNAMECollector(res, allSignatures)
		nsCollector := evidence.NewNSCollector(res, allSignatures)
		mxCollector := evidence.NewMXCollector(res, allSignatures)
		txtCollector := evidence.NewTXTCollector(allSignatures)
		srvCollector := evidence.NewSRVCollector(res, allSignatures)

		tlsCollector := evidence.NewTLSCollector(allSignatures, 2)
		tlsCollector.SetDialer(mock.TLSDialer())

		ipCollector := evidence.NewIPCollector(res, allSignatures)

		httpCollector := evidence.NewHTTPCollector(allSignatures, 2, "", false, "", false)
		httpCollector.SetTransport(mock.RoundTripper())

		registry := evidence.NewRegistry([]evidence.Collector{
			cnameCollector, nsCollector, mxCollector, txtCollector, srvCollector, tlsCollector, ipCollector, httpCollector,
		})

		verifierEngine := verifiers.NewEngine(verifiers.Config{
			Client: &http.Client{Transport: mock.RoundTripper()},
		})
		db, _ := storage.New(":memory:")

		engine := verify.NewEngine(res, registry, verifierEngine, db)

		hist := &core.HostAnalysis{
			Host:           tc.Host,
			Classification: "HEALTHY",
		}

		result, err := engine.Verify(context.Background(), hist)

		mock.Stop()

		if err != nil {
			fmt.Printf("Erro ao verificar %s: %v\n", tc.Host, err)
			continue
		}

		class := result.NewAnalysis.Classification

		// Valida a cobertura quando o caso define um valor esperado.
		cov := result.NewAnalysis.CoverageScore
		if tc.ExpectedCoverage > 0 && cov != float64(tc.ExpectedCoverage) {
			matrix.FailedCases = append(matrix.FailedCases, fmt.Sprintf("%s (cobertura esperada: %d, obtida: %.2f)", tc.Host, tc.ExpectedCoverage, cov))
			continue
		}

		// Atualiza a matriz de confusão.
		if class == string(tc.Classification) {
			if isTakeoverSignal(class) {
				matrix.TakeoverTP++
			} else {
				matrix.TakeoverTN++
			}
		} else {
			expectedTakeover := isTakeoverSignal(string(tc.Classification))
			actualTakeover := isTakeoverSignal(class)
			if expectedTakeover && !actualTakeover {
				matrix.TakeoverFN++
			} else if !expectedTakeover && actualTakeover {
				matrix.TakeoverFP++
			} else if expectedTakeover && actualTakeover {
				matrix.TakeoverTP++
			} else {
				matrix.TakeoverTN++
			}
			matrix.FailedCases = append(matrix.FailedCases, fmt.Sprintf("%s (esperado: %s, obtido: %s)", tc.Host, tc.Classification, class))
		}
	}

	matrix.Print()
	return len(matrix.FailedCases) == 0
}
