package benchmark

import (
	"fmt"
)

// ExpectedLabel representa a verdade de referência de um host.
type ExpectedLabel string

const (
	ExpectedTakeoverable     ExpectedLabel = "TAKEOVERABLE"
	ExpectedLikely           ExpectedLabel = "LIKELY_TAKEOVERABLE"
	ExpectedConfirmed        ExpectedLabel = "CONFIRMED_TAKEOVERABLE"
	ExpectedHealthy          ExpectedLabel = "HEALTHY"
	ExpectedOrphaned         ExpectedLabel = "ORPHANED"
	ExpectedMisconfigured    ExpectedLabel = "MISCONFIGURED"
	ExpectedDelegationBroken ExpectedLabel = "DELEGATION_BROKEN"
)

func isTakeoverSignal(label string) bool {
	return label == string(ExpectedLikely) || label == string(ExpectedTakeoverable) || label == string(ExpectedConfirmed) || label == "TAKEN_OVER" || label == "DELEGATION_CLAIMABILITY_VERIFIED" || label == "ZONE_CONTROL_CONFIRMED"
}

// MockState define as respostas simuladas para um host da suíte L3.
type MockState struct {
	DNS  *MockDNSState  `json:"dns,omitempty"`
	HTTP *MockHTTPState `json:"http,omitempty"`
	TLS  *MockTLSState  `json:"tls,omitempty"`
}

type MockDNSState struct {
	A     []string `json:"a,omitempty"`
	AAAA  []string `json:"aaaa,omitempty"`
	CNAME []string `json:"cname,omitempty"`
	NS    []string `json:"ns,omitempty"`
	MX    []string `json:"mx,omitempty"`
	TXT   []string `json:"txt,omitempty"`
	SRV   []string `json:"srv,omitempty"`
	// Campos adicionais podem representar falhas DNS em conjuntos controlados.
	NXDOMAIN bool `json:"nxdomain,omitempty"`
}

type MockHTTPState struct {
	Status  int               `json:"status,omitempty"`
	Body    string            `json:"body,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

type MockTLSState struct {
	Subject    string `json:"subject,omitempty"`
	Issuer     string `json:"issuer,omitempty"`
	Expired    bool   `json:"expired,omitempty"`
	SelfSigned bool   `json:"self_signed,omitempty"`
}

// TestCase representa um caso de teste das suítes L2 ou L3.
type TestCase struct {
	Host             string        `json:"host"`
	Classification   ExpectedLabel `json:"classification"` // Classificação de referência.
	Provider         string        `json:"provider,omitempty"`
	Verified         bool          `json:"verified,omitempty"`
	Source           string        `json:"source,omitempty"`
	ExpectedCoverage int           `json:"expected_coverage,omitempty"` // Cobertura esperada.

	// Utilizado apenas no L3 (suíte de regressão).
	Mock *MockState `json:"mock,omitempty"`
}

// Matrix representa a matriz de confusão do benchmark.
type Matrix struct {
	TotalRuns int

	TakeoverTP int // Verdadeiros positivos.
	TakeoverFP int // Falsos positivos.
	TakeoverTN int // Verdadeiros negativos.
	TakeoverFN int // Falsos negativos.

	// Divergências em relação à classificação esperada.
	FailedCases []string
}

// Recall retorna a proporção de casos vulneráveis detectados.
func (m *Matrix) Recall() float64 {
	den := float64(m.TakeoverTP + m.TakeoverFN)
	if den == 0 {
		return 100.0
	}
	return (float64(m.TakeoverTP) / den) * 100
}

// Precision retorna a proporção de alertas que correspondem a casos vulneráveis.
func (m *Matrix) Precision() float64 {
	den := float64(m.TakeoverTP + m.TakeoverFP)
	if den == 0 {
		return 100.0
	}
	return (float64(m.TakeoverTP) / den) * 100
}

// FNR retorna a taxa de falsos negativos.
func (m *Matrix) FNR() float64 {
	den := float64(m.TakeoverTP + m.TakeoverFN)
	if den == 0 {
		return 0.0
	}
	return (float64(m.TakeoverFN) / den) * 100
}

// FPR retorna a taxa de falsos positivos.
func (m *Matrix) FPR() float64 {
	den := float64(m.TakeoverFP + m.TakeoverTN)
	if den == 0 {
		return 0.0
	}
	return (float64(m.TakeoverFP) / den) * 100
}

func (m *Matrix) Print() {
	fmt.Println("\nResultados do benchmark")
	fmt.Println("=======================")
	fmt.Printf("Total de hosts:             %d\n\n", m.TotalRuns)
	fmt.Printf("Sensibilidade:              %.2f%%\n", m.Recall())
	fmt.Printf("Precisão:                   %.2f%%\n", m.Precision())
	fmt.Printf("Taxa de falsos negativos:   %.2f%%\n", m.FNR())
	fmt.Printf("Taxa de falsos positivos:   %.2f%%\n\n", m.FPR())

	if len(m.FailedCases) > 0 {
		fmt.Println("Casos com falha (regressões):")
		for _, f := range m.FailedCases {
			fmt.Printf(" - %s\n", f)
		}
	}
}
