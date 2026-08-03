package cmd

import (
	"errors"

	"github.com/amchdd/subdomainabber/pkg/config"
)

func loadCommandConfigWithError() (*config.Config, error) {
	cfg := config.Defaults()
	fileConfig, fileErr := config.LoadDefault()
	if fileErr == nil && fileConfig != nil {
		cfg = config.Merge(cfg, fileConfig)
	}
	environmentErr := config.ApplyEnv(cfg)
	applyGlobalFlags(cfg)
	return cfg, errors.Join(fileErr, environmentErr)
}

func loadRuntimeCommandConfig() (*config.Config, error) {
	cfg, err := loadCommandConfigWithError()
	if err != nil {
		return nil, err
	}
	if err := config.ValidateRuntime(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func applyGlobalFlags(cfg *config.Config) {
	if cfg == nil {
		return
	}
	if dbPath != "" {
		cfg.DBPath = dbPath
	}
	if verbose {
		cfg.Verbose = true
	}
	if silent {
		cfg.Silent = true
	}
	if noColor {
		cfg.NoColor = true
	}
	if discordMinSeverity != "" {
		cfg.DiscordMinSeverity = discordMinSeverity
	}
}
