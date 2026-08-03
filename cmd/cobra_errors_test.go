package cmd

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestOperationalCommandsPropagateErrorsThroughRunE(t *testing.T) {
	commands := []*cobra.Command{
		learnCmd,
		validateCmd,
		listCmd,
		coverageCmd,
		discoverCmd,
		benchmarkFingerprintsCmd,
		statsCmd,
		exportCmd,
	}

	for _, command := range commands {
		t.Run(command.CommandPath(), func(t *testing.T) {
			if command.Run != nil {
				t.Fatal("o comando ainda define Run e pode encerrar o processo sem propagar o erro")
			}
			if command.RunE == nil {
				t.Fatal("o comando não define RunE")
			}
		})
	}
}

func TestLoadConfiguredSignaturesReportsMissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "inexistente.json")

	_, err := loadConfiguredSignatures(missing, "")
	if err == nil {
		t.Fatal("era esperado erro ao carregar um arquivo de assinaturas inexistente")
	}
	if !strings.Contains(err.Error(), "erro ao carregar o arquivo de assinaturas") {
		t.Fatalf("erro sem contexto em PT-BR: %v", err)
	}
}
