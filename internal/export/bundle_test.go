package export

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
)

func TestSignedBundleDetectsChanges(t *testing.T) {
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "private.key")
	publicPath := filepath.Join(dir, "public.key")
	bundlePath := filepath.Join(dir, "evidence.json")
	if err := GenerateKey(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	if err := WriteBundle(bundlePath, "run-1", privatePath, []core.HostAnalysis{{Host: "app.example", Classification: "ORPHANED"}}); err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(bundlePath, publicPath); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	for index := range data {
		if data[index] == 'O' {
			data[index] = 'X'
			break
		}
	}
	if err := os.WriteFile(bundlePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(bundlePath, publicPath); err == nil {
		t.Fatal("alteração do bundle não foi detectada")
	}
}
