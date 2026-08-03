package cmd

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/storage"
	"github.com/amchdd/subdomainabber/internal/verify"
)

func TestRuntimeCommandConfigRejectsDisabledRateLimit(t *testing.T) {
	isolateDefaultConfigPath(t)
	t.Setenv("SABBER_RATE_LIMIT", "0")

	if _, err := loadRuntimeCommandConfig(); err == nil {
		t.Fatal("a configuração de rede aceitou o limitador desabilitado")
	}
}

func TestRuntimeCommandsValidateBeforeCreatingNetworkDependencies(t *testing.T) {
	isolateDefaultConfigPath(t)
	t.Setenv("SABBER_TIMEOUT", "-1")

	previousDomain := enumDomain
	enumDomain = "example.com"
	t.Cleanup(func() { enumDomain = previousDomain })

	if err := enumCmd.RunE(enumCmd, nil); err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("enum não rejeitou o tempo limite antes da execução: %v", err)
	}
	if err := verifyCmd.RunE(verifyCmd, nil); err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("verify não rejeitou o tempo limite antes da execução: %v", err)
	}
	if err := runScan(context.Background(), nil, nil); err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("scan não rejeitou o tempo limite antes da execução: %v", err)
	}
}

func TestEnumCommandRejectsInvalidWorkerCountBeforeNetworkSetup(t *testing.T) {
	isolateDefaultConfigPath(t)

	previousDomain := enumDomain
	previousConcurrency := enumConcurrency
	enumDomain = "example.com"
	enumConcurrency = 0
	t.Cleanup(func() {
		enumDomain = previousDomain
		enumConcurrency = previousConcurrency
	})

	err := enumCmd.RunE(enumCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "concorrência da enumeração") {
		t.Fatalf("enum não rejeitou a concorrência inválida: %v", err)
	}
}

func TestRuntimeCommandsReportResolverFileErrors(t *testing.T) {
	isolateDefaultConfigPath(t)
	missingResolvers := filepath.Join(t.TempDir(), "resolvedores-ausentes.txt")
	t.Setenv("SABBER_RESOLVERS_FILE", missingResolvers)

	previousDomain := enumDomain
	enumDomain = "example.com"
	t.Cleanup(func() { enumDomain = previousDomain })

	if err := enumCmd.RunE(enumCmd, nil); err == nil || !strings.Contains(err.Error(), "carregar resolvedores") {
		t.Fatalf("enum ignorou o erro do arquivo de resolvedores: %v", err)
	}

	databasePath := filepath.Join(t.TempDir(), "verify.db")
	store, err := storage.New(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAnalysis(&core.HostAnalysis{Host: "example.com", Classification: "UNKNOWN"}); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SABBER_DB_PATH", databasePath)

	previousDBPath := dbPath
	dbPath = ""
	t.Cleanup(func() { dbPath = previousDBPath })
	if err := verifyCmd.RunE(verifyCmd, nil); err == nil || !strings.Contains(err.Error(), "carregar resolvedores") {
		t.Fatalf("verify ignorou o erro do arquivo de resolvedores: %v", err)
	}
}

func TestPersistVerifiedAnalysisReportsClosedStore(t *testing.T) {
	store, err := storage.New(filepath.Join(t.TempDir(), "closed.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	result := &verify.Result{
		Host:        "example.com",
		NewAnalysis: &core.HostAnalysis{Host: "example.com", Classification: "UNKNOWN"},
	}
	if err := persistVerifiedAnalysis(store, result); err == nil || !strings.Contains(err.Error(), "salvando a análise") {
		t.Fatalf("falha de persistência não foi propagada: %v", err)
	}
}

func TestRunScanHonorsAlreadyCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runScan(ctx, []string{"example.com"}, nil); err != nil {
		t.Fatalf("cancelamento antecipado deveria encerrar sem ruído: %v", err)
	}
}

func isolateDefaultConfigPath(t *testing.T) {
	t.Helper()
	path := t.TempDir()
	t.Setenv("APPDATA", path)
	t.Setenv("AppData", path)
}
