// Package config centraliza o carregamento e a mesclagem de configurações do
// SubdomainAbber. A precedência (da menor para a maior) é:
//
//  1. Valores padrão
//  2. Arquivo YAML (~/.config/subdomainabber/config.yaml ou equivalente)
//  3. Variáveis de ambiente (prefixo SABBER_)
//  4. Opções da CLI (tratadas no pacote cmd)
//
// Todas as funções deste pacote são seguras para uso concorrente — nenhuma
// modifica estado global.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// configDirName é o nome do diretório dentro de os.UserConfigDir() onde o
// SubdomainAbber procura seu arquivo de configuração.
const configDirName = "subdomainabber"

// configFileName é o nome padrão do arquivo de configuração YAML.
const configFileName = "config.yaml"

// Config armazena todas as opções de configuração do SubdomainAbber.
// Campos com tag `yaml:"-"` são controlados exclusivamente via flags CLI.
type Config struct {
	// NoColor desabilita a formatação ANSI mesmo quando stdout é um terminal interativo.
	// Variável de ambiente: SABBER_NO_COLOR. A variável padrão NO_COLOR também é respeitada.
	NoColor bool `yaml:"no_color"`

	// Concurrency define o número de hosts processados simultaneamente.
	// Variável de ambiente: SABBER_CONCURRENCY
	Concurrency int `yaml:"concurrency"`

	// Timeout define o tempo limite de rede (em segundos) por operação. O
	// orçamento começa após a operação obter permissão do limitador global.
	// Variável de ambiente: SABBER_TIMEOUT
	Timeout int `yaml:"timeout"`

	// Verbose habilita saída detalhada de depuração.
	// Variável de ambiente: SABBER_VERBOSE
	Verbose bool `yaml:"verbose"`

	// Silent suprime o banner e os logs, mas preserva os resultados solicitados.
	// Variável de ambiente: SABBER_SILENT
	Silent bool `yaml:"silent"`

	// JSONOutput habilita saída em formato JSON em vez de texto plano.
	// Variável de ambiente: SABBER_JSON
	JSONOutput bool `yaml:"json_output"`

	// SigsFile é o caminho para um arquivo JSON com assinaturas de fingerprint.
	// Variável de ambiente: SABBER_SIGS_FILE
	SigsFile string `yaml:"sigs_file"`

	// SigsDir é o caminho para um diretório contendo múltiplos arquivos de assinatura.
	// Variável de ambiente: SABBER_SIGS_DIR
	SigsDir string `yaml:"sigs_dir"`

	// DBPath é o caminho do banco de dados SQLite para persistência de resultados.
	// Variável de ambiente: SABBER_DB_PATH
	DBPath string `yaml:"db_path"`

	// DiscordWebhook é a URL do webhook do Discord para notificações.
	// Variável de ambiente: SABBER_DISCORD_WEBHOOK
	DiscordWebhook string `yaml:"discord_webhook"`

	// DiscordMinSeverity filtra o volume de notificações. Valores aceitos:
	// info, low, medium, high e critical. Variável de ambiente: SABBER_DISCORD_MIN_SEVERITY.
	DiscordMinSeverity string `yaml:"discord_min_severity"`

	// TelegramConfig contém a configuração de notificação do Telegram
	// no formato "bot_token:chat_id".
	// Variável de ambiente: SABBER_TELEGRAM
	TelegramConfig string `yaml:"telegram"`

	// ResolversFile é o caminho para um arquivo com servidores DNS personalizados
	// (um por linha).
	// Variável de ambiente: SABBER_RESOLVERS_FILE
	ResolversFile string `yaml:"resolvers_file"`

	// RateLimit define o número máximo de operações por segundo. O valor zero
	// mantém o limite seguro padrão aplicado pela CLI.
	// Variável de ambiente: SABBER_RATE_LIMIT
	RateLimit int `yaml:"rate_limit"`

	// Proxy é a URL de um proxy HTTP/SOCKS5 para rotear todas as requisições.
	// Variável de ambiente: SABBER_PROXY
	Proxy string `yaml:"proxy"`

	// CheckNS habilita a verificação adicional de servidores NS para confirmar
	// a vulnerabilidade de takeover.
	// Variável de ambiente: SABBER_CHECK_NS
	CheckNS bool `yaml:"check_ns"`

	// NoWildcardFilter desabilita a filtragem automática de domínios curinga.
	// Variável de ambiente: SABBER_NO_WILDCARD_FILTER
	NoWildcardFilter bool `yaml:"no_wildcard_filter"`

	// Daemon habilita o modo contínuo processando a lista de alvos no intervalo configurado (ex.: 1h).
	// Variável de ambiente: SABBER_DAEMON
	Daemon string `yaml:"daemon"`

	// ConfigFile é o caminho explícito para o arquivo de configuração, definido
	// exclusivamente via flag --config. Não é lido/escrito pelo YAML.
	ConfigFile string `yaml:"-"`

	FollowRedirects bool   `yaml:"follow_redirects"`
	UserAgent       string `yaml:"user_agent"`
	DoH             string `yaml:"doh"`
	FetchHeaders    bool   `yaml:"headers"`

	// Tokens de APIs passivas e de nuvem
	AlienVaultToken  string `yaml:"alienvault_token"`
	CertSpotterToken string `yaml:"certspotter_token"`
	AwsAccessKey     string `yaml:"aws_access_key"`
	AwsSecretKey     string `yaml:"aws_secret_key"`
	AwsSessionToken  string `yaml:"aws_session_token"`
	AwsRegion        string `yaml:"aws_region"`
	UrlscanToken     string `yaml:"urlscan_token"`

	// Estas marcas distinguem um zero ausente de um zero escrito
	// explicitamente no YAML. Assim, a validação rejeita valores inseguros em
	// vez de substituí-los silenciosamente pelos padrões.
	concurrencyConfigured bool
	timeoutConfigured     bool
	rateLimitConfigured   bool
}

// Defaults retorna uma configuração com valores padrão sensatos para uso
// imediato. Esses valores são o ponto de partida antes de aplicar sobreposições
// de arquivo, variáveis de ambiente e flags CLI.
func Defaults() *Config {
	return &Config{
		Concurrency:        50,
		Timeout:            5,
		DBPath:             "subdomainabber.db",
		RateLimit:          10,
		AwsRegion:          "us-east-1",
		DiscordMinSeverity: "medium",
	}
}

// LoadFile carrega e interpreta um arquivo YAML de configuração a partir do
// caminho informado. Retorna erro se o arquivo não puder ser lido ou se o
// conteúdo YAML for inválido.
func LoadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: erro ao ler arquivo %q: %w", path, err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("config: erro ao interpretar o YAML de %q: %w", path, err)
	}

	var configuredNumbers struct {
		Concurrency *int `yaml:"concurrency"`
		Timeout     *int `yaml:"timeout"`
		RateLimit   *int `yaml:"rate_limit"`
	}
	if err := yaml.Unmarshal(data, &configuredNumbers); err != nil {
		return nil, fmt.Errorf("config: erro ao interpretar os valores numéricos de %q: %w", path, err)
	}
	cfg.concurrencyConfigured = configuredNumbers.Concurrency != nil
	cfg.timeoutConfigured = configuredNumbers.Timeout != nil
	cfg.rateLimitConfigured = configuredNumbers.RateLimit != nil

	return cfg, nil
}

// defaultConfigPath retorna o caminho completo para o arquivo de configuração
// padrão utilizando os.UserConfigDir() para compatibilidade multiplataforma.
//
// Caminhos típicos:
//   - Linux/macOS: ~/.config/subdomainabber/config.yaml
//   - Windows:     %APPDATA%\subdomainabber\config.yaml
func defaultConfigPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("config: impossível determinar diretório de configuração do usuário: %w", err)
	}

	return filepath.Join(dir, configDirName, configFileName), nil
}

// LoadDefault tenta carregar o arquivo de configuração do caminho padrão do
// sistema operacional. Se o arquivo não existir, retorna (nil, nil) — a
// ausência de configuração padrão não é considerada um erro.
//
// Se o arquivo existir mas não puder ser lido ou parseado, retorna erro.
func LoadDefault() (*Config, error) {
	path, err := defaultConfigPath()
	if err != nil {
		return nil, err
	}

	// Arquivo inexistente é silenciosamente ignorado — o usuário não é
	// obrigado a criar uma configuração.
	if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
		return nil, nil
	}

	return LoadFile(path)
}

// ApplyEnv lê variáveis de ambiente com prefixo SABBER_ e sobrescreve os
// campos correspondentes do Config fornecido. Apenas variáveis definidas e
// não-vazias causam sobreposição; variáveis ausentes ou vazias são ignoradas.
// Retorna erro quando uma variável numérica não contém um número inteiro.
//
// Para campos booleanos, os valores aceitos são: "1", "true", "yes", "on"
// (sem diferenciar maiúsculas de minúsculas) para verdadeiro. Qualquer outro
// valor é tratado como falso.
func ApplyEnv(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config: configuração ausente ao aplicar variáveis de ambiente")
	}

	var numericErrors []error

	// Campos inteiros
	if v := os.Getenv("SABBER_CONCURRENCY"); v != "" {
		n, err := parseEnvironmentInteger("SABBER_CONCURRENCY", v)
		if err != nil {
			numericErrors = append(numericErrors, err)
		} else {
			cfg.Concurrency = n
		}
	}
	if v := os.Getenv("SABBER_TIMEOUT"); v != "" {
		n, err := parseEnvironmentInteger("SABBER_TIMEOUT", v)
		if err != nil {
			numericErrors = append(numericErrors, err)
		} else {
			cfg.Timeout = n
		}
	}
	if v := os.Getenv("SABBER_RATE_LIMIT"); v != "" {
		n, err := parseEnvironmentInteger("SABBER_RATE_LIMIT", v)
		if err != nil {
			numericErrors = append(numericErrors, err)
		} else {
			cfg.RateLimit = n
		}
	}

	// Campos booleanos
	if v := os.Getenv("SABBER_VERBOSE"); v != "" {
		cfg.Verbose = parseBool(v)
	}
	if v := os.Getenv("SABBER_SILENT"); v != "" {
		cfg.Silent = parseBool(v)
	}
	if v := os.Getenv("SABBER_JSON"); v != "" {
		cfg.JSONOutput = parseBool(v)
	}
	if v := os.Getenv("SABBER_CHECK_NS"); v != "" {
		cfg.CheckNS = parseBool(v)
	}
	if v := os.Getenv("SABBER_NO_WILDCARD_FILTER"); v != "" {
		cfg.NoWildcardFilter = parseBool(v)
	}
	if v := os.Getenv("SABBER_FOLLOW_REDIRECTS"); v != "" {
		cfg.FollowRedirects = parseBool(v)
	}
	if v := os.Getenv("SABBER_FETCH_HEADERS"); v != "" {
		cfg.FetchHeaders = parseBool(v)
	}
	if v := os.Getenv("SABBER_NO_COLOR"); v != "" {
		cfg.NoColor = parseBool(v)
	}
	if os.Getenv("NO_COLOR") != "" {
		cfg.NoColor = true
	}

	// Campos string
	if v := os.Getenv("SABBER_SIGS_FILE"); v != "" {
		cfg.SigsFile = v
	}
	if v := os.Getenv("SABBER_SIGS_DIR"); v != "" {
		cfg.SigsDir = v
	}
	if v := os.Getenv("SABBER_DB_PATH"); v != "" {
		cfg.DBPath = v
	}
	if v := os.Getenv("SABBER_DISCORD_WEBHOOK"); v != "" {
		cfg.DiscordWebhook = v
	}
	if v := os.Getenv("SABBER_DISCORD_MIN_SEVERITY"); v != "" {
		cfg.DiscordMinSeverity = v
	}
	if v := os.Getenv("SABBER_TELEGRAM"); v != "" {
		cfg.TelegramConfig = v
	}
	if v := os.Getenv("SABBER_RESOLVERS_FILE"); v != "" {
		cfg.ResolversFile = v
	}
	if v := os.Getenv("SABBER_PROXY"); v != "" {
		cfg.Proxy = v
	}
	if v := os.Getenv("SABBER_DAEMON"); v != "" {
		cfg.Daemon = v
	}
	if v := os.Getenv("SABBER_USER_AGENT"); v != "" {
		cfg.UserAgent = v
	}

	// Tokens de API.
	if v := os.Getenv("SABBER_ALIENVAULT_TOKEN"); v != "" {
		cfg.AlienVaultToken = v
	}
	if v := os.Getenv("SABBER_CERTSPOTTER_TOKEN"); v != "" {
		cfg.CertSpotterToken = v
	}
	if v := os.Getenv("SABBER_AWS_ACCESS_KEY"); v != "" {
		cfg.AwsAccessKey = v
	}
	if v := os.Getenv("SABBER_AWS_SECRET_KEY"); v != "" {
		cfg.AwsSecretKey = v
	}
	if v := os.Getenv("SABBER_AWS_SESSION_TOKEN"); v != "" {
		cfg.AwsSessionToken = v
	}
	if v := os.Getenv("SABBER_AWS_REGION"); v != "" {
		cfg.AwsRegion = v
	}
	if v := os.Getenv("SABBER_URLSCAN_TOKEN"); v != "" {
		cfg.UrlscanToken = v
	}

	return errors.Join(numericErrors...)
}

// Merge combina duas configurações; `override` tem prioridade sobre `base`
// para qualquer campo com valor não-zero. Valores numéricos escritos
// explicitamente no YAML também são preservados, inclusive zero, para que o
// validador possa rejeitá-los. Retorna um novo Config; os originais não são
// modificados.
//
// A semântica de "valor não-zero" segue o padrão do Go:
//   - int: diferente de 0
//   - string: diferente de ""
//   - bool: diferente de false (ou seja, true sempre sobrescreve)
//
// Uma configuração `override` construída em Go ainda usa zero como "não configurado". No
// arquivo YAML, a presença explícita do campo é preservada para validação.
func Merge(base, override *Config) *Config {
	// Trata valores nil de forma defensiva para simplificar o uso pelo chamador.
	if base == nil && override == nil {
		return Defaults()
	}
	if base == nil {
		cpy := *override
		return &cpy
	}
	if override == nil {
		cpy := *base
		return &cpy
	}

	// Começa com uma cópia de `base` e aplica os valores de `override`.
	merged := *base

	if override.Concurrency != 0 || override.concurrencyConfigured {
		merged.Concurrency = override.Concurrency
		merged.concurrencyConfigured = override.concurrencyConfigured
	}
	if override.Timeout != 0 || override.timeoutConfigured {
		merged.Timeout = override.Timeout
		merged.timeoutConfigured = override.timeoutConfigured
	}
	if override.RateLimit != 0 || override.rateLimitConfigured {
		merged.RateLimit = override.RateLimit
		merged.rateLimitConfigured = override.rateLimitConfigured
	}

	// Para booleanos, true em `override` sempre sobrescreve o valor anterior.
	if override.Verbose {
		merged.Verbose = true
	}
	if override.Silent {
		merged.Silent = true
	}
	if override.JSONOutput {
		merged.JSONOutput = true
	}
	if override.CheckNS {
		merged.CheckNS = true
	}
	if override.NoWildcardFilter {
		merged.NoWildcardFilter = true
	}
	if override.FollowRedirects {
		merged.FollowRedirects = true
	}
	if override.FetchHeaders {
		merged.FetchHeaders = true
	}
	if override.NoColor {
		merged.NoColor = true
	}

	// Campos de texto só são sobrescritos quando não estão vazios.
	if override.SigsFile != "" {
		merged.SigsFile = override.SigsFile
	}
	if override.SigsDir != "" {
		merged.SigsDir = override.SigsDir
	}
	if override.DBPath != "" {
		merged.DBPath = override.DBPath
	}
	if override.DiscordWebhook != "" {
		merged.DiscordWebhook = override.DiscordWebhook
	}
	if override.DiscordMinSeverity != "" {
		merged.DiscordMinSeverity = override.DiscordMinSeverity
	}
	if override.TelegramConfig != "" {
		merged.TelegramConfig = override.TelegramConfig
	}
	if override.ResolversFile != "" {
		merged.ResolversFile = override.ResolversFile
	}
	if override.Proxy != "" {
		merged.Proxy = override.Proxy
	}
	if override.Daemon != "" {
		merged.Daemon = override.Daemon
	}
	if override.ConfigFile != "" {
		merged.ConfigFile = override.ConfigFile
	}
	if override.UserAgent != "" {
		merged.UserAgent = override.UserAgent
	}
	if override.DoH != "" {
		merged.DoH = override.DoH
	}

	// Tokens de API.
	if override.AlienVaultToken != "" {
		merged.AlienVaultToken = override.AlienVaultToken
	}
	if override.CertSpotterToken != "" {
		merged.CertSpotterToken = override.CertSpotterToken
	}
	if override.AwsAccessKey != "" {
		merged.AwsAccessKey = override.AwsAccessKey
	}
	if override.AwsSecretKey != "" {
		merged.AwsSecretKey = override.AwsSecretKey
	}
	if override.AwsSessionToken != "" {
		merged.AwsSessionToken = override.AwsSessionToken
	}
	if override.AwsRegion != "" {
		merged.AwsRegion = override.AwsRegion
	}
	if override.UrlscanToken != "" {
		merged.UrlscanToken = override.UrlscanToken
	}
	// Fatias: sobrescrever se houver elementos.
	return &merged
}

// parseBool interpreta uma string como valor booleano de forma permissiva.
// Aceita "1", "true", "yes" e "on" (sem diferenciar maiúsculas de minúsculas)
// como verdadeiro.
// Qualquer outro valor retorna falso.
func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func parseEnvironmentInteger(name, value string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("config: %s deve conter um número inteiro, mas recebeu %q", name, value)
	}
	return n, nil
}
