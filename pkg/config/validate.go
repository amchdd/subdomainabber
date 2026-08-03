package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// MinimumDaemonInterval impede que uma configuração incorreta transforme o
	// modo contínuo em um laço de varredura praticamente ininterrupto.
	MinimumDaemonInterval = time.Minute

	// MaximumEnumerationConcurrency limita a quantidade de goroutines abertas
	// simultaneamente por cada etapa da enumeração ativa.
	MaximumEnumerationConcurrency = 1000
)

// ValidateRuntime verifica os valores numéricos compartilhados pelos comandos
// que executam operações de rede. O limitador de taxa é obrigatório nesses
// comandos; valor zero nunca significa execução sem limite.
func ValidateRuntime(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("configuração de execução ausente")
	}
	if cfg.Concurrency < 1 {
		return fmt.Errorf("concurrency deve ser maior ou igual a 1 (valor recebido: %d)", cfg.Concurrency)
	}
	if cfg.Timeout <= 0 {
		return fmt.Errorf("timeout deve ser maior que zero (valor recebido: %d)", cfg.Timeout)
	}
	if cfg.RateLimit <= 0 {
		return fmt.Errorf("rate_limit deve ser maior que zero; o limite de segurança não pode ser desabilitado (valor recebido: %d)", cfg.RateLimit)
	}
	if err := validateDoHURL(cfg.DoH); err != nil {
		return err
	}
	if _, err := ParseDaemonInterval(cfg.Daemon); err != nil {
		return err
	}
	return nil
}

func validateDoHURL(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parsed, err := url.Parse(value)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Hostname() == "" {
		return fmt.Errorf("doh deve ser uma URL HTTPS absoluta válida")
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("doh não pode conter credenciais nem fragmento")
	}
	return nil
}

// ParseDaemonInterval interpreta e valida o intervalo do modo contínuo. Uma
// string vazia indica que o modo daemon está desabilitado.
func ParseDaemonInterval(value string) (time.Duration, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, nil
	}

	interval, err := time.ParseDuration(trimmed)
	if err != nil {
		return 0, fmt.Errorf("daemon: intervalo inválido %q: use uma duração como 30m ou 1h", value)
	}
	if interval < MinimumDaemonInterval {
		return 0, fmt.Errorf("daemon: o intervalo deve ser de pelo menos %s (valor recebido: %s)", MinimumDaemonInterval, interval)
	}
	return interval, nil
}

// ValidateEnumerationConcurrency protege as filas e os grupos de rotinas da
// enumeração contra valores que causariam deadlock, panic ou consumo excessivo
// de recursos.
func ValidateEnumerationConcurrency(value int) error {
	if value < 1 || value > MaximumEnumerationConcurrency {
		return fmt.Errorf("a concorrência da enumeração deve estar entre 1 e %d (valor recebido: %d)", MaximumEnumerationConcurrency, value)
	}
	return nil
}
