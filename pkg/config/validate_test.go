package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateRuntimeAcceptsSafeDefaults(t *testing.T) {
	if err := ValidateRuntime(Defaults()); err != nil {
		t.Fatalf("os valores padrão deveriam ser válidos: %v", err)
	}
}

func TestValidateRuntimeRejectsUnsafeNumericValues(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*Config)
		expected string
	}{
		{name: "concorrência zero", mutate: func(cfg *Config) { cfg.Concurrency = 0 }, expected: "concurrency"},
		{name: "concorrência negativa", mutate: func(cfg *Config) { cfg.Concurrency = -1 }, expected: "concurrency"},
		{name: "tempo limite zero", mutate: func(cfg *Config) { cfg.Timeout = 0 }, expected: "timeout"},
		{name: "tempo limite negativo", mutate: func(cfg *Config) { cfg.Timeout = -1 }, expected: "timeout"},
		{name: "limite de taxa zero", mutate: func(cfg *Config) { cfg.RateLimit = 0 }, expected: "rate_limit"},
		{name: "limite de taxa negativo", mutate: func(cfg *Config) { cfg.RateLimit = -1 }, expected: "rate_limit"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := Defaults()
			test.mutate(cfg)
			err := ValidateRuntime(cfg)
			if err == nil {
				t.Fatal("a configuração inválida foi aceita")
			}
			if !strings.Contains(err.Error(), test.expected) {
				t.Fatalf("erro sem o campo causal %q: %v", test.expected, err)
			}
		})
	}
}

func TestParseDaemonIntervalEnforcesSafeMinimum(t *testing.T) {
	for _, value := range []string{"inválido", "0s", "-1m", "59s"} {
		t.Run(value, func(t *testing.T) {
			if _, err := ParseDaemonInterval(value); err == nil {
				t.Fatalf("o intervalo inseguro %q foi aceito", value)
			}
		})
	}

	interval, err := ParseDaemonInterval(" 1m ")
	if err != nil {
		t.Fatalf("o intervalo mínimo deveria ser aceito: %v", err)
	}
	if interval != time.Minute {
		t.Fatalf("intervalo inesperado: %s", interval)
	}

	disabled, err := ParseDaemonInterval("  ")
	if err != nil || disabled != 0 {
		t.Fatalf("daemon desabilitado deveria produzir duração zero: %s, %v", disabled, err)
	}
}

func TestValidateEnumerationConcurrencyEnforcesBounds(t *testing.T) {
	for _, value := range []int{0, -1, MaximumEnumerationConcurrency + 1} {
		if err := ValidateEnumerationConcurrency(value); err == nil {
			t.Fatalf("a concorrência inválida %d foi aceita", value)
		}
	}
	for _, value := range []int{1, 50, MaximumEnumerationConcurrency} {
		if err := ValidateEnumerationConcurrency(value); err != nil {
			t.Fatalf("a concorrência válida %d foi rejeitada: %v", value, err)
		}
	}
}

func TestValidateRuntimeRejectsNilConfiguration(t *testing.T) {
	if err := ValidateRuntime(nil); err == nil {
		t.Fatal("uma configuração ausente foi aceita")
	}
}

func TestValidateRuntimeRejectsUnsafeDoHURL(t *testing.T) {
	for _, value := range []string{
		"http://resolver.example/dns-query",
		"https://user:secret@resolver.example/dns-query",
		"https://resolver.example/dns-query#fragmento",
		"resolver.example/dns-query",
	} {
		cfg := Defaults()
		cfg.DoH = value
		if err := ValidateRuntime(cfg); err == nil || !strings.Contains(err.Error(), "doh") {
			t.Fatalf("URL DoH insegura %q não foi rejeitada: %v", value, err)
		}
	}

	cfg := Defaults()
	cfg.DoH = "https://resolver.example/dns-query"
	if err := ValidateRuntime(cfg); err != nil {
		t.Fatalf("URL DoH válida foi rejeitada: %v", err)
	}
}

func TestExplicitZeroInYAMLIsNotSilentlyReplacedByDefault(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		expected string
	}{
		{name: "concorrência", contents: "concurrency: 0\n", expected: "concurrency"},
		{name: "tempo limite", contents: "timeout: 0\n", expected: "timeout"},
		{name: "limite de taxa", contents: "rate_limit: 0\n", expected: "rate_limit"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(test.contents), 0o600); err != nil {
				t.Fatalf("não foi possível criar a configuração temporária: %v", err)
			}
			fileConfig, err := LoadFile(path)
			if err != nil {
				t.Fatalf("não foi possível carregar a configuração: %v", err)
			}
			merged := Merge(Defaults(), fileConfig)
			err = ValidateRuntime(merged)
			if err == nil || !strings.Contains(err.Error(), test.expected) {
				t.Fatalf("o zero explícito em %s não foi rejeitado: %v", test.expected, err)
			}
		})
	}
}
