package benchmark

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVersionedRegression(t *testing.T) {
	if !RunL3Regression(filepath.Join("..", "..", "datasets", "regression")) {
		t.Fatal("o conjunto versionado encontrou regressões")
	}
}

func TestRegressionRejectsInvalidCases(t *testing.T) {
	for name, data := range map[string]string{
		"json":       "{",
		"incompleto": `{}`,
		"status":     `{"host":"example.test","classification":"UNKNOWN","mock":{"http":{"status":0}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "case.json"), []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			if RunL3Regression(dir) {
				t.Fatal("um caso inválido foi aprovado")
			}
		})
	}
}
