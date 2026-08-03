package config

import "testing"

func TestApplyEnvAndMergeSupportTemporaryAWSCredentials(t *testing.T) {
	t.Setenv("SABBER_AWS_ACCESS_KEY", "temporary-access")
	t.Setenv("SABBER_AWS_SECRET_KEY", "temporary-secret")
	t.Setenv("SABBER_AWS_SESSION_TOKEN", "temporary-session")
	t.Setenv("SABBER_AWS_REGION", "sa-east-1")
	t.Setenv("SABBER_FOLLOW_REDIRECTS", "true")
	t.Setenv("SABBER_FETCH_HEADERS", "true")
	t.Setenv("SABBER_USER_AGENT", "SubdomainAbber/config-test")
	t.Setenv("SABBER_DISCORD_MIN_SEVERITY", "high")
	t.Setenv("SABBER_NO_COLOR", "true")

	cfg := Defaults()
	if err := ApplyEnv(cfg); err != nil {
		t.Fatalf("não foi possível aplicar as variáveis de ambiente: %v", err)
	}
	if cfg.AwsAccessKey != "temporary-access" || cfg.AwsSecretKey != "temporary-secret" || cfg.AwsSessionToken != "temporary-session" || cfg.AwsRegion != "sa-east-1" {
		t.Fatalf("AWS environment was not applied: %#v", cfg)
	}
	if !cfg.FollowRedirects || !cfg.FetchHeaders || cfg.UserAgent != "SubdomainAbber/config-test" {
		t.Fatalf("HTTP environment was not applied: %#v", cfg)
	}
	if cfg.DiscordMinSeverity != "high" || !cfg.NoColor {
		t.Fatalf("output environment was not applied: %#v", cfg)
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
