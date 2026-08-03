package benchmark

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

type GoldEntry struct {
	Host             string `json:"host"`
	Classification   string `json:"classification"`
	Provider         string `json:"provider"`
	Verified         bool   `json:"verified"`
	VerifiedAt       string `json:"verified_at,omitempty"`
	Authorization    string `json:"authorization,omitempty"`
	Source           string `json:"source"`
	Reference        string `json:"reference,omitempty"`
	ExpectedEvidence string `json:"expected_evidence,omitempty"`
}

func RunL2Gold(ctx context.Context, datasetPath string) (runErr error) {
	fmt.Println("Iniciando benchmark L2 com o conjunto de dados de referência...")

	matrix := &Matrix{}

	allSignatures := signatures.MergeSignatures(signatures.BuiltinNSSignatures())
	embeddedSigs, err := signatures.LoadEmbedded()
	if err != nil {
		return fmt.Errorf("erro ao carregar as assinaturas embutidas: %w", err)
	}
	allSignatures = append(allSignatures, embeddedSigs...)

	res := dns.New([]string{"8.8.8.8:53"})

	cnameCollector := evidence.NewCNAMECollector(res, allSignatures)
	nsCollector := evidence.NewNSCollector(res, allSignatures)
	mxCollector := evidence.NewMXCollector(res, allSignatures)
	txtCollector := evidence.NewTXTCollector(allSignatures)
	srvCollector := evidence.NewSRVCollector(res, allSignatures)
	tlsCollector := evidence.NewTLSCollector(allSignatures, 2)
	ipCollector := evidence.NewIPCollector(res, allSignatures)
	httpCollector := evidence.NewHTTPCollector(allSignatures, 5, "", false, "", false)

	registry := evidence.NewRegistry([]evidence.Collector{
		cnameCollector, nsCollector, mxCollector, txtCollector, srvCollector, tlsCollector, ipCollector, httpCollector,
	})

	verifierEngine := verifiers.NewEngine(verifiers.Config{})
	db, err := storage.New(":memory:")
	if err != nil {
		return fmt.Errorf("erro ao criar o banco de dados temporário: %w", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("erro ao fechar o banco de dados temporário: %w", err))
		}
	}()

	engine := verify.NewEngine(res, registry, verifierEngine, db)

	// Percorre os arquivos JSON do conjunto de dados.
	var testCases []TestCase
	err = filepath.Walk(datasetPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".json" {
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("erro ao ler o caso de teste %q: %w", path, err)
			}
			var entry GoldEntry
			if err := json.Unmarshal(data, &entry); err != nil {
				return fmt.Errorf("JSON inválido no caso de teste %q: %w", path, err)
			}
			// Arquivos não verificados servem apenas como modelos de esquema. O
			// benchmark nunca deve transformar um exemplo público em alvo de rede.
			if !entry.Verified {
				return nil
			}

			// Converte a classificação persistida para o rótulo esperado.
			expected := ExpectedHealthy
			if entry.Classification == "TAKEOVERABLE" {
				expected = ExpectedTakeoverable
			} else if entry.Classification == "ORPHANED" {
				expected = ExpectedOrphaned
			}

			testCases = append(testCases, TestCase{
				Host:           entry.Host,
				Classification: expected,
			})
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("erro ao percorrer o conjunto de dados %q: %w", datasetPath, err)
	}

	if len(testCases) == 0 {
		fmt.Println("Nenhum caso verificado encontrado; use somente casos controlados e autorizados")
		return nil
	}

	for _, tc := range testCases {
		matrix.TotalRuns++

		hist := &core.HostAnalysis{
			Host:           tc.Host,
			Classification: "HEALTHY",
		}

		result, err := engine.Verify(ctx, hist)
		if err != nil {
			fmt.Printf("Erro ao verificar %s: %v\n", tc.Host, err)
			continue
		}

		class := result.NewAnalysis.Classification
		if class == "CONFIRMED_TAKEOVERABLE" {
			class = "TAKEOVERABLE"
		}

		// Atualiza a matriz de confusão.
		if class == "TAKEOVERABLE" {
			if tc.Classification == ExpectedTakeoverable {
				matrix.TakeoverTP++
			} else {
				matrix.TakeoverFP++
				matrix.FailedCases = append(matrix.FailedCases, fmt.Sprintf("%s (esperado: %s, obtido: %s)", tc.Host, tc.Classification, class))
			}
		} else {
			if tc.Classification == ExpectedTakeoverable {
				matrix.TakeoverFN++
				matrix.FailedCases = append(matrix.FailedCases, fmt.Sprintf("%s (esperado: %s, obtido: %s)", tc.Host, tc.Classification, class))
			}
		}
	}

	matrix.Print()
	return nil
}
