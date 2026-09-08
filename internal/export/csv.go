package export

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/amchdd/subdomainabber/internal/core"
)

type CSVExporter struct {
	file string
}

func NewCSVExporter(file string) *CSVExporter {
	return &CSVExporter{file: file}
}

func (c *CSVExporter) Export(ctx context.Context, hosts []core.HostAnalysis) error {
	out := os.Stdout
	if c.file != "" {
		var err error
		out, err = os.Create(c.file)
		if err != nil {
			return fmt.Errorf("criando arquivo csv: %w", err)
		}
		defer out.Close()
	}

	w := csv.NewWriter(out)
	defer w.Flush()

	// Escreve o cabeçalho sem traduzir os campos estruturados.
	header := []string{
		"Host",
		"Classification",
		"ResultState",
		"RiskScore",
		"MitigationScore",
		"ConfidenceScore",
		"ObservationConfidence",
		"ClassificationConfidence",
		"ImpactConfidence",
		"ImpactConfirmed",
		"DecisionRule",
		"HTTPStatus",
		"HTTPSStatus",
		"HTTPResponseKind",
		"HTTPSResponseKind",
		"HTTPEdgeProvider",
		"HTTPSEdgeProvider",
		"BodySimilarity",
		"TransportPriority",
		"CNAME",
		"first_seen",
		"last_seen",
		"evidence_count",
		"evidences_summary",
	}
	if err := w.Write(header); err != nil {
		return fmt.Errorf("escrevendo cabeçalho CSV: %w", err)
	}

	for _, h := range hosts {
		evTypes := []string{}
		for _, ev := range h.Evidences {
			evTypes = append(evTypes, ev.Type)
		}
		evSummary := strings.Join(evTypes, "|")

		observationConfidence, classificationConfidence, impactConfidence := 0, 0, 0
		impactConfirmed := false
		decisionRule := ""
		if h.Decision != nil {
			observationConfidence = h.Decision.ObservationConfidence
			classificationConfidence = h.Decision.ClassificationConfidence
			impactConfidence = h.Decision.ImpactConfidence
			impactConfirmed = h.Decision.ImpactConfirmed
			decisionRule = h.Decision.Rule
		}
		httpStatus, httpsStatus, similarity, priority := 0, 0, 0.0, 0
		httpKind, httpsKind, httpEdge, httpsEdge := "", "", "", ""
		if h.HTTPCorrelation != nil {
			httpStatus = h.HTTPCorrelation.HTTPStatus
			httpsStatus = h.HTTPCorrelation.HTTPSStatus
			similarity = h.HTTPCorrelation.BodySimilarity
			priority = h.HTTPCorrelation.TransportPriority
			httpKind = h.HTTPCorrelation.HTTPResponseKind
			httpsKind = h.HTTPCorrelation.HTTPSResponseKind
			httpEdge = h.HTTPCorrelation.HTTPEdgeProvider
			httpsEdge = h.HTTPCorrelation.HTTPSEdgeProvider
		}

		record := []string{
			h.Host,
			h.Classification,
			string(h.ResultState),
			fmt.Sprintf("%d", h.RiskScore),
			fmt.Sprintf("%d", h.MitigationScore),
			fmt.Sprintf("%d", h.ConfidenceScore),
			strconv.Itoa(observationConfidence),
			strconv.Itoa(classificationConfidence),
			strconv.Itoa(impactConfidence),
			strconv.FormatBool(impactConfirmed),
			decisionRule,
			strconv.Itoa(httpStatus),
			strconv.Itoa(httpsStatus),
			httpKind,
			httpsKind,
			httpEdge,
			httpsEdge,
			strconv.FormatFloat(similarity, 'f', 1, 64),
			strconv.Itoa(priority),
			strings.Join(h.DNS.CNAME, "; "),
			h.FirstSeen.Format("2006-01-02T15:04:05Z"),
			h.LastSeen.Format("2006-01-02T15:04:05Z"),
			strconv.Itoa(len(h.Evidences)),
			evSummary,
		}

		if err := w.Write(record); err != nil {
			return fmt.Errorf("escrevendo linha csv: %w", err)
		}
	}

	return nil
}
