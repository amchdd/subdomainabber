package config

import (
	"os"
	"testing"
)

func TestDefaultsEnableRedirectAnalysis(t *testing.T) {
	cfg := Defaults()
	if !cfg.FollowRedirects || cfg.RedirectDepth != 10 {
		t.Fatalf("análise padrão de redirects inesperada: %#v", cfg)
	}
}

func TestMergeHonorsExplicitRedirectDisable(t *testing.T) {
	path := t.TempDir() + "/config.yaml"
	if err := os.WriteFile(path, []byte("follow_redirects: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	merged := Merge(Defaults(), file)
	if merged.FollowRedirects {
		t.Fatal("follow_redirects: false não desabilitou a análise")
	}
}

func TestApplyEnvAndMergeSupportTemporaryAWSCredentials(t *testing.T) {
	t.Setenv("SABBER_AWS_ACCESS_KEY", "temporary-access")
	t.Setenv("SABBER_AWS_SECRET_KEY", "temporary-secret")
	t.Setenv("SABBER_AWS_SESSION_TOKEN", "temporary-session")
	t.Setenv("SABBER_AWS_REGION", "sa-east-1")
	t.Setenv("SABBER_FOLLOW_REDIRECTS", "true")
	t.Setenv("SABBER_REDIRECT_DEPTH", "7")
	t.Setenv("SABBER_FETCH_HEADERS", "true")
	t.Setenv("SABBER_USER_AGENT", "SubdomainAbber/config-test")
	t.Setenv("SABBER_DISCORD_MIN_SEVERITY", "high")
	t.Setenv("SABBER_NO_COLOR", "true")
	t.Setenv("SABBER_WEBHOOK", "https://hooks.example.test/eventos")
	t.Setenv("SABBER_WEBHOOK_SECRET", "segredo-webhook")

	cfg := Defaults()
	if err := ApplyEnv(cfg); err != nil {
		t.Fatalf("não foi possível aplicar as variáveis de ambiente: %v", err)
	}
	if cfg.AwsAccessKey != "temporary-access" || cfg.AwsSecretKey != "temporary-secret" || cfg.AwsSessionToken != "temporary-session" || cfg.AwsRegion != "sa-east-1" {
		t.Fatalf("AWS environment was not applied: %#v", cfg)
	}
	if !cfg.FollowRedirects || cfg.RedirectDepth != 7 || !cfg.FetchHeaders || cfg.UserAgent != "SubdomainAbber/config-test" {
		t.Fatalf("HTTP environment was not applied: %#v", cfg)
	}
	if cfg.DiscordMinSeverity != "high" || !cfg.NoColor {
		t.Fatalf("output environment was not applied: %#v", cfg)
	}
	if cfg.WebhookURL != "https://hooks.example.test/eventos" || cfg.WebhookSecret != "segredo-webhook" {
		t.Fatalf("configuração do webhook não foi aplicada: %#v", cfg)
	}

	merged := Merge(Defaults(), &Config{AwsSessionToken: "merged-session"})
	if merged.AwsSessionToken != "merged-session" {
		t.Fatalf("AWS session token was not merged: %q", merged.AwsSessionToken)
	}
	merged = Merge(Defaults(), &Config{DiscordMinSeverity: "critical", NoColor: true})
	if merged.DiscordMinSeverity != "critical" || !merged.NoColor {
		t.Fatalf("output configuration was not merged: %#v", merged)
	}
}

func TestPlatformCredentialsSupportYAMLEnvironmentAndMerge(t *testing.T) {
	path := t.TempDir() + "/platforms.yaml"
	data := []byte("hackerone_username: pesquisador\nhackerone_token: arquivo\nintigriti_token: arquivo-intigriti\nbugcrowd_token: arquivo-bugcrowd\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if file.HackerOneUsername != "pesquisador" || file.BugcrowdToken != "arquivo-bugcrowd" {
		t.Fatalf("credenciais YAML incompletas: %#v", file)
	}

	t.Setenv("SABBER_HACKERONE_TOKEN", "ambiente-h1")
	t.Setenv("SABBER_INTIGRITI_TOKEN", "ambiente-intigriti")
	cfg := Merge(Defaults(), file)
	if err := ApplyEnv(cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.HackerOneToken != "ambiente-h1" || cfg.IntigritiToken != "ambiente-intigriti" {
		t.Fatalf("precedência de ambiente incorreta: %#v", cfg)
	}
	merged := Merge(cfg, &Config{BugcrowdToken: "sobreposto"})
	if merged.BugcrowdToken != "sobreposto" {
		t.Fatalf("merge não aplicou token: %#v", merged)
	}
}

func TestSecurityTrailsTokenSupportsEnvironmentAndMerge(t *testing.T) {
	t.Setenv("SABBER_SECURITYTRAILS_TOKEN", "ambiente")
	cfg := Defaults()
	if err := ApplyEnv(cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.SecurityTrailsToken != "ambiente" {
		t.Fatalf("token do SecurityTrails não aplicado: %q", cfg.SecurityTrailsToken)
	}
	merged := Merge(cfg, &Config{SecurityTrailsToken: "sobreposto"})
	if merged.SecurityTrailsToken != "sobreposto" {
		t.Fatalf("token do SecurityTrails não mesclado: %q", merged.SecurityTrailsToken)
	}
}

func TestApplyEnvPreservesInvalidNumericValueForRuntimeValidation(t *testing.T) {
	t.Setenv("SABBER_RATE_LIMIT", "0")

	cfg := Defaults()
	if err := ApplyEnv(cfg); err != nil {
		t.Fatalf("não foi possível aplicar a variável numérica: %v", err)
	}
	if cfg.RateLimit != 0 {
		t.Fatalf("o valor inválido deveria chegar ao validador; recebido: %d", cfg.RateLimit)
	}
	if err := ValidateRuntime(cfg); err == nil {
		t.Fatal("o limite de taxa igual a zero foi aceito")
	}
}

func TestApplyEnvRejectsMalformedNumericValue(t *testing.T) {
	t.Setenv("SABBER_TIMEOUT", "cinco")
	t.Setenv("SABBER_DB_PATH", "resultados.db")

	cfg := Defaults()
	if err := ApplyEnv(cfg); err == nil {
		t.Fatal("uma variável numérica malformada foi ignorada")
	}
	if cfg.DBPath != "resultados.db" {
		t.Fatalf("uma variável inválida impediu a aplicação das demais: %q", cfg.DBPath)
	}
}
