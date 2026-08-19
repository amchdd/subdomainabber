package benchmark

import (
	"path/filepath"
	"testing"
)

func TestVersionedCorpus(t *testing.T) {
	result, err := RunCorpus(filepath.Join("..", "..", "datasets", "corpus"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Total < 4 || result.Failed != 0 {
		t.Fatalf("resultado inesperado: %+v", result)
	}
}
