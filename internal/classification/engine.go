package classification

import (
	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/inference"
)

// Process calcula as pontuações e define a classificação final da análise.
func Process(analysis *core.HostAnalysis) {
	inference.Analyze(analysis)
	CalculateScores(analysis)

	// As regras semânticas prevalecem sobre a pontuação bruta.
	analysis.Classification = Classify(analysis)

	// Provedores desconhecidos reduzem a confiança e alimentam a revisão do catálogo.
	DetectUnknownProvider(analysis)
}
