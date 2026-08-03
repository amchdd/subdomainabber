package export

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/amchdd/subdomainabber/internal/core"
)

// JSONExporter implementa a exportação estruturada.
type JSONExporter struct {
	file string
}

func NewJSONExporter(file string) *JSONExporter {
	return &JSONExporter{file: file}
}

// ExportContainer envolve o vetor de hosts com o versionamento do esquema.
type ExportContainer struct {
	SchemaVersion string              `json:"schema_version"`
	Results       []core.HostAnalysis `json:"results"`
}

func (j *JSONExporter) Export(ctx context.Context, hosts []core.HostAnalysis) error {
	container := ExportContainer{
		SchemaVersion: "v1",
		Results:       hosts,
	}

	out := os.Stdout
	if j.file != "" {
		var err error
		out, err = os.Create(j.file)
		if err != nil {
			return fmt.Errorf("criando arquivo json: %w", err)
		}
		defer out.Close()
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(container); err != nil {
		return fmt.Errorf("gerando json: %w", err)
	}

	return nil
}
