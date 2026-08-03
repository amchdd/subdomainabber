package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/amchdd/subdomainabber/internal/buildinfo"
	"github.com/spf13/cobra"
)

type commandContextKey struct{}

func TestCLIReportsAlphaReleaseVersionWithoutGlobalSideEffects(t *testing.T) {
	if buildinfo.Version != "v0.1.0-alpha" || rootCmd.Version != buildinfo.Version {
		t.Fatalf("versions = buildinfo:%q cobra:%q", buildinfo.Version, rootCmd.Version)
	}
	if rootCmd.PersistentPreRun != nil || rootCmd.PersistentPreRunE != nil {
		t.Fatal("root command has a side-effecting persistent pre-run hook")
	}
}

func TestRootHelpIsPortugueseOnlyAndDoesNotExposeLanguageFlag(t *testing.T) {
	usage := rootCmd.UsageString()
	for _, expected := range []string{"Uso:", "Comandos disponíveis:", "Opções:"} {
		if !strings.Contains(usage, expected) {
			t.Fatalf("ajuda não contém %q:\n%s", expected, usage)
		}
	}
	for _, unexpected := range []string{"Available Commands:", "Global Flags:", "--lang"} {
		if strings.Contains(usage, unexpected) {
			t.Fatalf("ajuda ainda contém %q:\n%s", unexpected, usage)
		}
	}
}

func TestCobraErrorsArePresentedInPortuguese(t *testing.T) {
	tests := map[string]string{
		"unknown flag: --lang":                       "flag desconhecida: --lang",
		`unknown command "foo" for "subdomainabber"`: `comando desconhecido "foo" para "subdomainabber"`,
		"accepts 1 arg(s), received 0":               "aceita 1 argumento(s), recebeu 0",
		`invalid argument "nope" for "-t, --timeout" flag: strconv.ParseInt: parsing "nope": invalid syntax`: `argumento inválido "nope" para "-t, --timeout": era esperado um número inteiro`,
		`invalid argument "talvez" for "--json" flag: strconv.ParseBool: parsing "talvez": invalid syntax`:   `argumento inválido "talvez" para "--json": era esperado true ou false`,
		`invalid argument "amanhã" for "--changed-since" flag: time: invalid duration "amanhã"`:              `argumento inválido "amanhã" para "--changed-since": era esperado um intervalo, como 30s, 5m ou 1h`,
	}
	for input, expected := range tests {
		if got := localizeCLIError(errors.New(input)); got != expected {
			t.Fatalf("localizeCLIError(%q) = %q; esperado %q", input, got, expected)
		}
	}
}

func TestReleaseCLIExposesOnlyImplementedScanFlags(t *testing.T) {
	for _, name := range []string{"evasion", "list", "discord-webhook", "aggressive", "aggressive-confirm-auto-claim", "aggressive-allowlist"} {
		if scanCmd.Flags().Lookup(name) == nil {
			t.Fatalf("implemented --%s flag is missing", name)
		}
	}
	for _, name := range []string{"check-exotic", "turbo", "discord", "telegram"} {
		if scanCmd.Flags().Lookup(name) != nil {
			t.Fatalf("legacy or unimplemented --%s flag is registered", name)
		}
	}
}

func TestRootArgumentsRouteDirectScanUsage(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"direct list", []string{"-l", "alvo.txt", "--check-all"}, []string{"scan", "-l", "alvo.txt", "--check-all"}},
		{"direct host", []string{"assets.example.com", "--evasion"}, []string{"scan", "assets.example.com", "--evasion"}},
		{"global before scan flag", []string{"--verbose", "-l", "alvo.txt"}, []string{"scan", "--verbose", "-l", "alvo.txt"}},
		{"explicit scan", []string{"scan", "-l", "alvo.txt"}, []string{"scan", "-l", "alvo.txt"}},
		{"other command", []string{"verify", "--only-risky"}, []string{"verify", "--only-risky"}},
		{"help command", []string{"help", "scan"}, []string{"help", "scan"}},
		{"help alias", []string{"ajuda", "scan"}, []string{"ajuda", "scan"}},
		{"root version", []string{"--version"}, []string{"--version"}},
		{"db value named scan", []string{"--db", "scan", "-l", "alvo.txt"}, []string{"scan", "--db", "scan", "-l", "alvo.txt"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := routeRootArgs(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("routeRootArgs(%#v) = %#v, want %#v", tt.in, got, tt.want)
			}
			for index := range got {
				if got[index] != tt.want[index] {
					t.Fatalf("routeRootArgs(%#v) = %#v, want %#v", tt.in, got, tt.want)
				}
			}
		})
	}
}

func TestExecuteContextPropagatesContextToCobraCommand(t *testing.T) {
	want := "contexto-da-execução"
	probe := &cobra.Command{
		Use: "context-probe",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if got := cmd.Context().Value(commandContextKey{}); got != want {
				t.Fatalf("contexto recebido = %#v; esperado %q", got, want)
			}
			return nil
		},
	}
	rootCmd.AddCommand(probe)
	t.Cleanup(func() {
		rootCmd.RemoveCommand(probe)
		rootCmd.SetArgs(nil)
		rootCmd.SetContext(context.Background())
	})

	ctx := context.WithValue(context.Background(), commandContextKey{}, want)
	if err := executeContext(ctx, []string{"context-probe"}); err != nil {
		t.Fatal(err)
	}
}
