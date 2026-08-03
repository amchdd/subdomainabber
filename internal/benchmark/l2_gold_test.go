package benchmark

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunL2GoldReportsInvalidJSON(t *testing.T) {
	dataset := t.TempDir()
	path := filepath.Join(dataset, "caso.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatalf("erro ao preparar fixture: %v", err)
	}

	err := RunL2Gold(context.Background(), dataset)
	if err == nil {
		t.Fatal("era esperado erro para um caso de teste com JSON inválido")
	}
	if !strings.Contains(err.Error(), "JSON inválido") {
		t.Fatalf("erro sem contexto sobre o JSON inválido: %v", err)
	}
}
