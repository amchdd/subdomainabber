package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"

	"github.com/amchdd/subdomainabber/internal/buildinfo"
	"github.com/spf13/cobra"
)

var invalidFlagArgumentPattern = regexp.MustCompile(`^invalid argument (.+?) for "([^"]+)" flag: (.+)$`)

var (
	verbose            bool
	silent             bool
	dbPath             string
	noColor            bool
	discordMinSeverity string
)

var rootCmd = &cobra.Command{
	Use:           "subdomainabber",
	Short:         "Ferramenta de varredura de takeover de subdomínio para pesquisa autorizada",
	Long:          fmt.Sprintf("SubdomainAbber %s — ferramenta de varredura de takeover de subdomínio para pesquisa autorizada", buildinfo.Version),
	Version:       buildinfo.Version,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := executeContext(ctx, os.Args[1:])
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, localizeCLIError(err))
		os.Exit(1)
	}
}

func executeContext(ctx context.Context, args []string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	rootCmd.SetArgs(routeRootArgs(args))
	return rootCmd.ExecuteContext(ctx)
}

func commandContext(cmd *cobra.Command) context.Context {
	if cmd != nil && cmd.Context() != nil {
		return cmd.Context()
	}
	return context.Background()
}

func localizeCLIError(err error) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	if matches := invalidFlagArgumentPattern.FindStringSubmatch(message); len(matches) == 4 {
		expected := "um valor válido"
		switch {
		case strings.Contains(matches[3], "strconv.ParseInt"), strings.Contains(matches[3], "strconv.ParseUint"):
			expected = "um número inteiro"
		case strings.Contains(matches[3], "strconv.ParseFloat"):
			expected = "um número"
		case strings.Contains(matches[3], "strconv.ParseBool"):
			expected = "true ou false"
		case strings.Contains(matches[3], "invalid duration"):
			expected = "um intervalo, como 30s, 5m ou 1h"
		}
		return fmt.Sprintf("argumento inválido %s para %q: era esperado %s", matches[1], matches[2], expected)
	}
	replacements := []struct{ from, to string }{
		{"unknown shorthand flag:", "flag curta desconhecida:"},
		{"unknown flag:", "flag desconhecida:"},
		{"unknown command", "comando desconhecido"},
		{"Did you mean this?", "Você quis dizer?"},
		{"Did you mean one of these?", "Você quis dizer um destes?"},
		{" for ", " para "},
		{"flag needs an argument:", "a flag exige um argumento:"},
		{"required flag(s)", "flag(s) obrigatória(s)"},
		{" not set", " não definida(s)"},
		{"accepts ", "aceita "},
		{" arg(s), received ", " argumento(s), recebeu "},
		{"invalid argument", "argumento inválido"},
	}
	for _, replacement := range replacements {
		message = strings.ReplaceAll(message, replacement.from, replacement.to)
	}
	return message
}

// routeRootArgs preserva subcomandos explícitos e trata flags ou hosts
// fornecidos diretamente como uma execução implícita de "scan".
func routeRootArgs(args []string) []string {
	if len(args) == 0 {
		return args
	}

	commands := make(map[string]struct{}, len(rootCmd.Commands()))
	commands["help"] = struct{}{}
	commands["ajuda"] = struct{}{}
	for _, command := range rootCmd.Commands() {
		commands[command.Name()] = struct{}{}
		for _, alias := range command.Aliases {
			commands[alias] = struct{}{}
		}
	}

	for index := 0; index < len(args); index++ {
		arg := args[index]
		switch {
		case arg == "--db", arg == "--discord-min-severity":
			index++
			continue
		case strings.HasPrefix(arg, "--db="), strings.HasPrefix(arg, "--discord-min-severity="):
			continue
		case arg == "--verbose", arg == "-v", arg == "--silent", arg == "--no-color", arg == "--version", arg == "--help", arg == "-h":
			continue
		case strings.HasPrefix(arg, "-"):
			return append([]string{"scan"}, args...)
		default:
			if _, explicitCommand := commands[arg]; explicitCommand {
				return args
			}
			return append([]string{"scan"}, args...)
		}
	}

	return args
}

func init() {
	rootCmd.SetVersionTemplate("{{.Version}}\n")
	rootCmd.SetUsageTemplate(`Uso:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [comando]{{end}}{{if gt (len .Aliases) 0}}

Apelidos:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Exemplos:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}{{$cmds := .Commands}}{{if eq (len .Groups) 0}}

Comandos disponíveis:{{range $cmds}}{{if (or .IsAvailableCommand (eq .Name "help") (eq .Name "ajuda"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{else}}{{range $group := .Groups}}

{{.Title}}{{range $cmds}}{{if (and (eq .GroupID $group.ID) (or .IsAvailableCommand (eq .Name "help") (eq .Name "ajuda")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if not .AllChildCommandsHaveGroup}}

Comandos adicionais:{{range $cmds}}{{if (and (eq .GroupID "") (or .IsAvailableCommand (eq .Name "help") (eq .Name "ajuda")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

Opções:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

Opções globais:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Tópicos adicionais de ajuda:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [comando] --help" para obter mais informações sobre um comando.{{end}}
`)
	rootCmd.SetHelpCommand(&cobra.Command{
		Use:     "ajuda [comando]",
		Aliases: []string{"help"},
		Short:   "Exibe ajuda sobre qualquer comando",
		Args:    cobra.ArbitraryArgs,
		RunE: func(command *cobra.Command, args []string) error {
			target, _, err := command.Root().Find(args)
			if err != nil {
				return err
			}
			return target.Help()
		},
	})
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.PersistentFlags().BoolP("help", "h", false, "Exibe a ajuda do comando")
	rootCmd.Flags().Bool("version", false, "Exibe a versão do SubdomainAbber")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Habilitar saída verbosa e mensagens de depuração no stderr")
	rootCmd.PersistentFlags().BoolVar(&silent, "silent", false, "Modo silencioso — suprime banner e logs, imprime apenas resultados")
	rootCmd.PersistentFlags().StringVar(&dbPath, "db", "", "Caminho para banco SQLite de deduplicação (padrão subdomainabber.db)")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Desabilitar cores ANSI na saída da CLI")
	rootCmd.PersistentFlags().StringVar(&discordMinSeverity, "discord-min-severity", "", "Severidade mínima do Discord: info, low, medium, high ou critical")
}
