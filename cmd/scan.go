package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/amchdd/subdomainabber/internal/buildinfo"
	claimengine "github.com/amchdd/subdomainabber/internal/claim"
	"github.com/amchdd/subdomainabber/internal/classification"
	"github.com/amchdd/subdomainabber/internal/confidence"
	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/discovery"
	"github.com/amchdd/subdomainabber/internal/dns"
	"github.com/amchdd/subdomainabber/internal/evidence"
	"github.com/amchdd/subdomainabber/internal/netclient"
	"github.com/amchdd/subdomainabber/internal/presentation"
	"github.com/amchdd/subdomainabber/internal/report"
	"github.com/amchdd/subdomainabber/internal/storage"
	"github.com/amchdd/subdomainabber/internal/verifiers"
	"github.com/amchdd/subdomainabber/pkg/color"
	"github.com/amchdd/subdomainabber/pkg/config"
	"github.com/amchdd/subdomainabber/pkg/notify"
	"github.com/amchdd/subdomainabber/pkg/ratelimit"
	"github.com/amchdd/subdomainabber/pkg/signatures"

	"github.com/spf13/cobra"
)

var (
	scanQuiet            bool
	scanExplain          bool
	scanExplainJ         bool
	scanShowInconclusive bool
	scanMinSeverity      string
	scanConcurrency      int
	timeout              int
	jsonOutput           bool
	sigsFile             string
	sigsDir              string
	resolversFile        string
	rateLimit            int
	checkNS              bool
	proxy                string
	configFile           string
	noWildcard           bool
	daemon               string
	scanInputList        string
	discordWebhook       string

	// Novas flags de análise
	checkCloud          bool
	checkAXFR           bool
	checkDNSSEC         bool
	checkEmail          bool
	checkHeaders        bool
	checkShadowIT       bool
	checkRedirects      bool
	checkAll            bool
	checkEvasion        bool
	checkSRV            bool
	srvOwners           string
	srvExhaustive       bool
	configuredSRVOwners []string
	checkFraming        bool
	framingControlled   bool
	framingAllowlist    string

	whoisPivot          bool
	whoisPivotConfirm   bool
	whoisPivotAllowlist string
	aggressive          bool
	aggressiveConfirm   bool
	aggressiveAllowlist string
)

var scanCmd = &cobra.Command{
	Use:   "scan [host ...]",
	Short: "Analisa hosts fornecidos por argumento, arquivo ou entrada padrão (stdin)",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		domains, err := loadScanDomains(args, scanInputList, cmd.InOrStdin(), stdinHasPipedData(os.Stdin))
		if err != nil {
			return err
		}
		claimTargets, err := aggressiveClaimTargets(aggressive, aggressiveConfirm, aggressiveAllowlist, domains)
		if err != nil {
			return err
		}
		return runScan(commandContext(cmd), domains, claimTargets)
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().BoolVarP(&scanQuiet, "quiet", "q", false, "Exibe apenas hosts com achados relevantes (takeover, exposição ou configuração quebrada)")
	scanCmd.Flags().BoolVar(&scanExplain, "explain", false, "Exibe o detalhamento de como a classificação e a pontuação foram calculadas")
	scanCmd.Flags().BoolVar(&scanExplainJ, "explain-json", false, "Exibe a explicação matemática e sintética estruturada em JSON")
	scanCmd.Flags().BoolVar(&scanShowInconclusive, "show-inconclusive", false, "Exibe blocos humanos para UNKNOWN e INSUFFICIENT_EVIDENCE")
	scanCmd.Flags().StringVar(&scanMinSeverity, "min-severity", "", "Severidade mínima do CLI: info, low, medium, high ou critical (vazio = todos os achados)")
	scanCmd.Flags().IntVarP(&scanConcurrency, "concurrency", "c", 0, "Número de hosts processados simultaneamente (0 = usa configuração ou padrão de 50)")
	scanCmd.Flags().IntVarP(&timeout, "timeout", "t", 0, "Tempo limite de rede por operação, em segundos, iniciado após a permissão do limitador")
	scanCmd.Flags().BoolVar(&jsonOutput, "json", false, "Saída dos resultados como JSON Lines (ndjson)")
	scanCmd.Flags().StringVar(&sigsFile, "sigs", "", "Caminho para arquivo JSON de assinaturas local")
	scanCmd.Flags().StringVar(&sigsDir, "sigs-dir", "", "Diretório com arquivos JSON de assinaturas adicionais")
	scanCmd.Flags().StringVarP(&resolversFile, "resolvers", "r", "", "Caminho para arquivo de resolvedores DNS personalizados")
	scanCmd.Flags().IntVar(&rateLimit, "rl", 0, "Limite global de operações por segundo (0 = usa o padrão seguro de 10)")
	scanCmd.Flags().BoolVar(&checkNS, "check-ns", false, "Habilitar detecção de NS takeover")
	scanCmd.Flags().StringVar(&proxy, "proxy", "", "URL ou arquivo/lista de proxies HTTP/SOCKS5")
	scanCmd.Flags().StringVar(&configFile, "config", "", "Caminho para arquivo de configuração YAML")
	scanCmd.Flags().BoolVar(&noWildcard, "no-wildcard-filter", false, "Desabilitar filtro de wildcard DNS")
	scanCmd.Flags().StringVar(&daemon, "daemon", "", "Habilitar modo contínuo com intervalo (ex.: 1h, 30m)")
	scanCmd.Flags().StringVarP(&scanInputList, "list", "l", "", "Arquivo com um host por linha")
	scanCmd.Flags().StringVar(&discordWebhook, "discord-webhook", "", "Webhook do Discord para achados relevantes (prefira SABBER_DISCORD_WEBHOOK para não expor o segredo no histórico)")

	scanCmd.Flags().BoolVar(&checkAll, "check-all", false, "Habilita NS, SRV, AXFR, nuvem, e-mail, cabeçalhos, DNSSEC, Shadow IT e redirecionamentos; não habilita evasão, framing nem modo agressivo")
	scanCmd.Flags().BoolVar(&checkCloud, "check-cloud", false, "Habilitar verificação de exposição em nuvem (S3, Blob e GCS)")
	scanCmd.Flags().BoolVar(&checkAXFR, "check-axfr", false, "Tentar transferência de zona (AXFR)")
	scanCmd.Flags().BoolVar(&checkDNSSEC, "check-dnssec", false, "Inspecionar artefatos DNSSEC sem afirmar validação da cadeia")
	scanCmd.Flags().BoolVar(&checkEmail, "check-email", false, "Analisar segurança de e-mail (SPF/DMARC)")
	scanCmd.Flags().BoolVar(&checkSRV, "check-srv", false, "Enumerar uma lista controlada de nomes proprietários SRV comuns além do hostname de entrada")
	scanCmd.Flags().StringVar(&srvOwners, "srv-owners", "", "Nomes proprietários SRV adicionais separados por vírgula (ex.: _sip._tcp,_ldap._tcp)")
	scanCmd.Flags().BoolVar(&srvExhaustive, "srv-exhaustive", false, "Enumerar nomes proprietários SRV em cada host, em vez de uma vez por domínio registrável")
	scanCmd.Flags().BoolVar(&checkHeaders, "check-headers", false, "Analisar cabeçalhos de segurança HTTP (HSTS/CSP)")
	scanCmd.Flags().BoolVar(&checkShadowIT, "check-shadowit", false, "Detectar serviços SaaS não monitorados (Shadow IT)")
	scanCmd.Flags().BoolVar(&checkRedirects, "check-redirects", false, "Realizar testes ativos de redirecionamento aberto (Open Redirect)")
	scanCmd.Flags().BoolVar(&checkEvasion, "evasion", false, "Executar sondas HTTP de evasão controlada com comparação da linha de base; exige autorização do programa")
	scanCmd.Flags().BoolVar(&checkFraming, "check-framing", false, "Laboratório experimental CL.TE/TE.CL; somente ambiente controlado e autorizado")
	scanCmd.Flags().BoolVar(&framingControlled, "framing-confirm-controlled", false, "Confirma que todos os alvos de framing pertencem a ambiente controlado com autorização específica")
	scanCmd.Flags().StringVar(&framingAllowlist, "framing-allowlist", "", "Lista permitida explícita de autoridades para framing (separada por vírgula ou arquivo)")

	scanCmd.Flags().BoolVar(&whoisPivot, "whois-pivot", false, "Descobrir domínios raiz da mesma empresa por WHOIS reverso")
	scanCmd.Flags().BoolVar(&whoisPivotConfirm, "whois-pivot-confirm", false, "Confirma que você possui permissão contratual para testar escopo reverso expandido")
	scanCmd.Flags().StringVar(&whoisPivotAllowlist, "whois-pivot-allowlist", "", "Lista exata de domínios registráveis autorizados para inclusão após o pivotamento (separada por vírgula ou arquivo)")
	scanCmd.Flags().BoolVar(&aggressive, "aggressive", false, "Habilita reivindicação automática real para provedores suportados; exige confirmação, lista permitida e credenciais")
	scanCmd.Flags().BoolVar(&aggressiveConfirm, "aggressive-confirm-auto-claim", false, "Confirma autorização específica para criar e liberar recursos nos hosts permitidos")
	scanCmd.Flags().StringVar(&aggressiveAllowlist, "aggressive-allowlist", "", "Lista exata de hosts autorizados para reivindicação automática (separada por vírgula ou arquivo)")
}

func runScan(ctx context.Context, domains, claimTargets []string) (runErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return nil
	}

	// Carrega a configuração na ordem arquivo, ambiente e flags.
	cfg := config.Defaults()

	var fileCfg *config.Config
	var err error
	if configFile != "" {
		fileCfg, err = config.LoadFile(configFile)
		if err != nil {
			return fmt.Errorf("erro ao carregar configuração: %w", err)
		}
	} else {
		fileCfg, err = config.LoadDefault()
		if err != nil {
			return fmt.Errorf("erro ao carregar configuração: %w", err)
		}
	}
	if fileCfg != nil {
		cfg = config.Merge(cfg, fileCfg)
	}

	if err := config.ApplyEnv(cfg); err != nil {
		return err
	}

	cliCfg := &config.Config{}
	if scanConcurrency != 0 {
		cliCfg.Concurrency = scanConcurrency
	}
	if timeout != 0 {
		cliCfg.Timeout = timeout
	}
	if jsonOutput {
		cliCfg.JSONOutput = true
	}
	if sigsFile != "" {
		cliCfg.SigsFile = sigsFile
	}
	if sigsDir != "" {
		cliCfg.SigsDir = sigsDir
	}
	if resolversFile != "" {
		cliCfg.ResolversFile = resolversFile
	}
	if rateLimit != 0 {
		cliCfg.RateLimit = rateLimit
	}
	if proxy != "" {
		cliCfg.Proxy = proxy
	}
	if checkAll {
		enableCheckAllModules()
	}
	if checkSRV {
		configuredSRVOwners, err = parseSRVOwners(srvOwners)
		if err != nil {
			return err
		}
	}

	if checkNS {
		cliCfg.CheckNS = true
	}
	if noWildcard {
		cliCfg.NoWildcardFilter = true
	}
	if daemon != "" {
		cliCfg.Daemon = daemon
	}
	if discordWebhook != "" {
		cliCfg.DiscordWebhook = discordWebhook
	}
	if scanQuiet {
		cliCfg.Silent = true
	}
	cfg = config.Merge(cfg, cliCfg)
	applyGlobalFlags(cfg)
	if err := config.ValidateRuntime(cfg); err != nil {
		return fmt.Errorf("configuração de execução inválida: %w", err)
	}
	if err := validateScanOutputModes(cfg); err != nil {
		return err
	}
	if scanMinSeverity != "" {
		if _, err := notify.ParseSeverity(scanMinSeverity); err != nil {
			return fmt.Errorf("--min-severity: %w", err)
		}
	}
	if err := validateAggressiveRuntime(aggressive, cfg.Daemon); err != nil {
		return err
	}

	debugLog := log.New(io.Discard, "[DEPURAÇÃO] ", log.LstdFlags|log.Lmsgprefix)
	if cfg.Verbose {
		debugLog.SetOutput(os.Stderr)
	}

	logInfo := func(format string, a ...interface{}) {
		if !cfg.Silent {
			fmt.Fprintf(os.Stderr, format, a...)
		}
	}

	if !cfg.Silent {
		fmt.Fprintf(os.Stderr, `
   ▄▄▄▄▄   ▄   ███   ██▄   ████▄ █▀▄▀█ ██   ▄█    ▄   ██   ███   ███   ▄███▄   █▄▄▄▄ 
  █     ▀▄  █  █  █  █  █  █   █ █ █ █ █ █  ██     █  █ █  █  █  █  █  █▀   ▀  █  ▄▀ 
▄  ▀▀▀▀▄ █   █ █ ▀ ▄ █   █ █   █ █ ▄ █ █▄▄█ ██ ██   █ █▄▄█ █ ▀ ▄ █ ▀ ▄ ██▄▄    █▀▀▌  
 ▀▄▄▄▄▀  █   █ █  ▄▀ █  █  ▀████ █   █ █  █ ▐█ █ █  █ █  █ █  ▄▀ █  ▄▀ █▄   ▄▀ █  █  
         █▄ ▄█ ███   ███▀           █     █  ▐ █  █ █    █ ███   ███   ▀███▀     █   
          ▀▀▀                      ▀     █     █   ██   █                       ▀    
                                        ▀              ▀                             

                  subdomainabber %s — Ferramenta de varredura de takeover de subdomínio
                                desenvolvido por amchdd
`, buildinfo.Version)
	}

	logInfo("[*] Carregando assinaturas...\n")
	var allSignatures []signatures.Fingerprint

	embeddedSigs, err := signatures.LoadEmbedded()
	if err == nil {
		allSignatures = append(allSignatures, embeddedSigs...)
	} else {
		return fmt.Errorf("erro ao carregar o catálogo embutido: %w", err)
	}

	if cfg.SigsFile != "" {
		localSigs, err := signatures.LoadFromFile(cfg.SigsFile)
		if err != nil {
			return fmt.Errorf("erro ao ler assinaturas de %s: %w", cfg.SigsFile, err)
		}
		allSignatures = append(allSignatures, localSigs...)
	}

	if cfg.SigsDir != "" {
		dirSigs, err := signatures.LoadFromDir(cfg.SigsDir)
		if err != nil {
			return fmt.Errorf("erro ao ler o diretório de assinaturas: %w", err)
		}
		if len(dirSigs) > 0 {
			allSignatures = append(allSignatures, dirSigs...)
			logInfo("[*] %d assinaturas adicionais mescladas do diretório\n", len(dirSigs))
		}
	}

	if cfg.CheckNS {
		nsSigs := signatures.BuiltinNSSignatures()
		allSignatures = append(allSignatures, nsSigs...)
		logInfo("[*] %d assinaturas NS embutidas adicionadas (Amazon Web Services, Microsoft Azure, DigitalOcean e Google Cloud)\n", len(nsSigs))
	}

	allSignatures = signatures.MergeSignatures(allSignatures)
	signatureDigest, err := signatures.Digest(allSignatures)
	if err != nil {
		return err
	}
	scanProfile := currentScanProfile(cfg, signatureDigest)

	logInfo("[*] Assinaturas carregadas: %d\n", len(allSignatures))

	logInfo("[*] Inicializando banco de dados em %s... ", cfg.DBPath)
	db, err := storage.New(cfg.DBPath)
	if err != nil {
		logInfo("FALHOU\n")
		return fmt.Errorf("erro no banco de dados: %w", err)
	}
	defer closeStoreWithError(db, &runErr)
	logInfo("OK\n")

	var autoClaimer *claimengine.Engine
	if aggressive {
		s3Provider, providerErr := claimengine.NewAWSS3Provider(ctx, cfg.AwsRegion, cfg.AwsAccessKey, cfg.AwsSecretKey, cfg.AwsSessionToken)
		if providerErr != nil {
			return fmt.Errorf("a reivindicação automática agressiva não pôde carregar as credenciais AWS: %w", providerErr)
		}
		route53Provider, providerErr := claimengine.NewAWSRoute53Provider(ctx, cfg.AwsRegion, cfg.AwsAccessKey, cfg.AwsSecretKey, cfg.AwsSessionToken)
		if providerErr != nil {
			return fmt.Errorf("a validação ativa do Amazon Route 53 não pôde carregar as credenciais da AWS: %w", providerErr)
		}
		autoClaimer, err = claimengine.NewEngine(db, claimTargets, s3Provider, route53Provider)
		if err != nil {
			return fmt.Errorf("configuração da reivindicação automática recusada: %w", err)
		}
		if err := autoClaimer.Reconcile(ctx); err != nil {
			return fmt.Errorf("ainda há liberações de reivindicação automática pendentes: %w", err)
		}
		logInfo("[!] Modo agressivo ativo: criação temporária habilitada para Amazon S3 e Amazon Route 53, limitada à lista permitida; os recursos serão verificados e liberados imediatamente.\n")
	}

	var customResolvers []string
	if cfg.ResolversFile != "" {
		resolvers, err := dns.LoadResolversFromFile(cfg.ResolversFile)
		if err != nil {
			return fmt.Errorf("erro ao carregar resolvedores: %w", err)
		}
		customResolvers = resolvers
		logInfo("[*] %d resolvedores DNS personalizados carregados\n", len(customResolvers))
	}

	res := dns.New(customResolvers)
	res.SetTimeout(time.Duration(cfg.Timeout) * time.Second)
	res.SetWildcardFiltering(!cfg.NoWildcardFilter)
	if err := configureResolverDoH(res, cfg); err != nil {
		return err
	}

	limiter := ratelimit.New(cfg.RateLimit)
	res.SetRequestLimiter(limiter)
	if limiter.Enabled() {
		logInfo("[*] Limite global habilitado: %d operações/s\n", cfg.RateLimit)
	}
	globalClient, clientErr := netclient.NewScopedClient(time.Duration(cfg.Timeout)*time.Second, cfg.Proxy, limiter)
	if clientErr != nil {
		return fmt.Errorf("erro ao configurar o cliente HTTP compartilhado: %w", clientErr)
	}

	cnameCollector := evidence.NewCNAMECollector(res, allSignatures)
	nsCollector := evidence.NewNSCollector(res, allSignatures)
	mxCollector := evidence.NewMXCollector(res, allSignatures)
	txtCollector := evidence.NewTXTCollector(allSignatures)
	srvCollector := evidence.NewSRVCollector(res, allSignatures)
	tlsCollector := evidence.NewTLSCollector(allSignatures, time.Duration(cfg.Timeout)*time.Second)
	ipCollector := evidence.NewIPCollector(res, allSignatures)
	caaCollector := evidence.NewCAACollector()
	httpCollector := evidence.NewHTTPCollector(allSignatures, time.Duration(cfg.Timeout)*time.Second, cfg.Proxy, cfg.FollowRedirects, cfg.UserAgent, cfg.FetchHeaders)
	if err := httpCollector.Validate(); err != nil {
		return fmt.Errorf("configurando o coletor HTTP: %w", err)
	}
	cookieCollector := evidence.NewCookieScopeCollector(time.Duration(cfg.Timeout)*time.Second, globalClient)
	corsCollector := evidence.NewCORSScopeCollector(time.Duration(cfg.Timeout)*time.Second, globalClient)
	cookieCollector.SetAllowedRootDomains(domains)
	corsCollector.SetAllowedRootDomains(domains)
	tlsCollector.SetRequestLimiter(limiter)
	httpCollector.SetRequestLimiter(limiter)

	collectors := []evidence.Collector{
		cnameCollector,
		mxCollector,
		txtCollector,
		srvCollector,
		tlsCollector,
		ipCollector,
		caaCollector,
		httpCollector,
		cookieCollector,
		corsCollector,
	}
	if cfg.CheckNS {
		collectors = append(collectors, nsCollector)
	}

	if checkEmail {
		emailCollector := evidence.NewEmailSecurityCollector(res)
		emailCollector.SetSignatures(allSignatures)
		collectors = append(collectors, emailCollector)
	}
	if checkHeaders || checkRedirects {
		securityCollector := evidence.NewHttpSecurityCollectorForChecks(checkHeaders, checkRedirects, globalClient)
		collectors = append(collectors, securityCollector)
	}
	if checkShadowIT {
		collectors = append(collectors, evidence.NewShadowITCollector())
	}
	if checkAXFR {
		collectors = append(collectors, evidence.NewZoneTransferCollector(res))
	}
	if checkDNSSEC {
		collectors = append(collectors, evidence.NewDNSSECCollector(res))
	}
	if checkEvasion {
		mutator := evidence.NewHTTPMutatorCollector(allSignatures, time.Duration(cfg.Timeout)*time.Second)
		mutator.SetRequestLimiter(limiter)
		mutator.SetLimits(7, time.Duration(cfg.Timeout)*4*time.Second)
		if err := mutator.ConfigureProxy(cfg.Proxy); err != nil {
			return fmt.Errorf("erro ao configurar o proxy do HTTP Mutator: %w", err)
		}
		collectors = append(collectors, mutator)
	}
	framingCollector, framingErr := newFramingCollectorIfAuthorized(checkFraming, framingControlled, framingAllowlist, time.Duration(cfg.Timeout)*time.Second)
	if framingErr != nil {
		return fmt.Errorf("configuração insegura de framing recusada: %w", framingErr)
	}
	if framingCollector != nil {
		framingCollector.SetRequestLimiter(limiter)
		framingCollector.SetLimits(2, time.Duration(cfg.Timeout)*4*time.Second)
		if err := framingCollector.ConfigureProxy(cfg.Proxy); err != nil {
			return fmt.Errorf("erro ao configurar o proxy do laboratório de framing: %w", err)
		}
		collectors = append(collectors, framingCollector)
		logInfo("[!] Framing experimental ativo somente para a lista permitida controlada. Não execute em infraestrutura de terceiros sem autorização específica.\n")
	}

	registry := evidence.NewRegistry(collectors)

	verifierEngine := verifiers.NewEngine(verifiers.Config{
		Client:     globalClient,
		CheckCloud: checkCloud,
	})
	dispatcher, dispatcherErr := notify.NewDispatcherWithOptions(notify.DispatcherConfig{
		Workers: 3, DiscordWebhook: cfg.DiscordWebhook, TelegramConfig: cfg.TelegramConfig,
		MinimumSeverity: cfg.DiscordMinSeverity,
	})
	if dispatcherErr != nil {
		return fmt.Errorf("configurando notificações: %w", dispatcherErr)
	}
	defer dispatcher.Flush()

	effectiveConcurrency := effectiveHostConcurrency(cfg.Concurrency, cfg.RateLimit)
	if effectiveConcurrency != cfg.Concurrency {
		logInfo("[*] Processamentos simultâneos efetivos: %d (%d solicitados; ajustados ao limite de %d operações/s; tempo limite de rede: %ds)\n", effectiveConcurrency, cfg.Concurrency, cfg.RateLimit, cfg.Timeout)
	} else {
		logInfo("[*] Iniciando varredura com %d processamentos simultâneos (tempo limite de rede: %ds)...\n", effectiveConcurrency, cfg.Timeout)
	}
	if checkAll {
		logInfo("[*] Perfil intensivo ativo: --check-all compartilha o limite global entre DNS, HTTP, TLS, NS, AXFR e verificadores.\n")
	}
	if cfg.Proxy != "" {
		logInfo("[*] Proxy HTTP/SOCKS5 configurado.\n")
	}
	if cfg.CheckNS {
		logInfo("[*] Detecção de NS takeover habilitada\n")
	}
	if cfg.NoWildcardFilter {
		logInfo("[*] Filtro de wildcard DNS desabilitado\n")
	}

	pivotTargets, err := authorizedWhoisPivotTargets(whoisPivot, whoisPivotConfirm, whoisPivotAllowlist)
	if err != nil {
		return err
	}
	if whoisPivot {
		fmt.Fprintf(os.Stderr, "\n[*] Pivotamento WHOIS ativo para o primeiro host fornecido; somente domínios da lista permitida poderão entrar na varredura.\n")
	} else {
		logInfo("[*] %d host(s) carregado(s) para análise.\n\n", len(domains))
	}

	if whoisPivot && len(domains) > 0 {
		// Pega o primeiro domínio (ou os primeiros) e faz o pivô
		targetRoot := dns.ExtractRootDomain(domains[0])

		pivotSvc := discovery.NewWhoisPivotService(globalClient)
		siblings, err := pivotSvc.Pivot(ctx, targetRoot)
		if err != nil {
			return fmt.Errorf("falha no pivotamento WHOIS para %s: %w", targetRoot, err)
		}

		fmt.Fprintf(os.Stderr, "\n[*] O pivotamento WHOIS localizou %d domínios relacionados a %s:\n", len(siblings), targetRoot)
		for _, s := range siblings {
			fmt.Fprintf(os.Stderr, "  - %s\n", s)
		}

		selected := selectDiscoveredWhoisTargets(siblings, pivotTargets)
		if len(selected) == 0 {
			fmt.Fprintln(os.Stderr, "[*] Nenhum domínio descoberto pertence à lista permitida; a varredura continuará somente com os alvos originais.")
		} else {
			domains = appendUniqueDomains(domains, selected)
			fmt.Fprintf(os.Stderr, "[+] %d domínio(s) explicitamente autorizado(s) adicionado(s) à fila.\n", len(selected))
		}
	}
	cookieCollector.SetAllowedRootDomains(domains)
	corsCollector.SetAllowedRootDomains(domains)
	explicitRoots := explicitRootDomains(domains)

	var daemonInterval time.Duration
	if strings.TrimSpace(cfg.Daemon) != "" {
		var err error
		daemonInterval, err = config.ParseDaemonInterval(cfg.Daemon)
		if err != nil {
			return fmt.Errorf("configuração de execução inválida: %w", err)
		}
		logInfo("[*] Modo daemon ativado. Intervalo da varredura: %s\n", daemonInterval)
	}

	outMu := &sync.Mutex{}

	for {
		batchCtx, cancelBatch := context.WithCancel(ctx)
		// Limpa o cache do resolver no início de cada iteração do daemon
		res.ClearCache()
		registry.BeginBatch()
		dispatcher.BeginBatch()
		outputDeduper := newScanFindingDeduper()

		var (
			wg         sync.WaitGroup
			sem        = make(chan struct{}, effectiveConcurrency)
			found      int
			foundMu    sync.Mutex
			fatalMu    sync.Mutex
			firstFatal error
		)
		progress := newScanProgress(
			len(domains),
			cfg.Concurrency,
			effectiveConcurrency,
			limiter,
			os.Stderr,
			!cfg.Silent && (cfg.Verbose || writerIsTerminal(os.Stderr)),
		)
		progress.Start()

	domainLoop:
		for _, domain := range domains {
			select {
			case <-batchCtx.Done():
				break domainLoop
			case sem <- struct{}{}:
			}

			wg.Add(1)

			go func(d string) {
				defer wg.Done()
				defer func() { <-sem }()

				progress.HostStarted()
				startedAt := time.Now()
				result := processDomain(batchCtx, d, registry, verifierEngine, autoClaimer, res, db, dispatcher, cfg, scanProfile, explicitRoots, outputDeduper, debugLog, outMu, &found, &foundMu)
				progress.HostFinished(result)
				if result.FatalErr != nil {
					fatalMu.Lock()
					if firstFatal == nil {
						firstFatal = result.FatalErr
						cancelBatch()
					}
					fatalMu.Unlock()
				}
				if result.Outcome != domainCanceled {
					detail := result.Outcome.String()
					if result.Classification != "" {
						detail += ", " + result.Classification
					}
					debugLog.Printf("Concluído %s em %s (%s)", d, time.Since(startedAt).Round(time.Millisecond), detail)
				}
			}(domain)
		}

		wg.Wait()
		cancelBatch()
		progress.Stop()

		snapshot := progress.Snapshot()
		fatalMu.Lock()
		fatalErr := firstFatal
		fatalMu.Unlock()
		if ctx.Err() != nil || fatalErr != nil {
			logInfo("\n[*] Varredura interrompida. %d concluídos, %d ignorados, %d falharam, %d cancelados e %d não iniciados.\n",
				snapshot.Completed, snapshot.Skipped, snapshot.Failed, snapshot.Canceled, snapshot.NotStarted)
		} else {
			if snapshot.Processed == 1 {
				logInfo("\n[*] Varredura concluída. 1 host processado, %d achados relevantes encontrados.\n", found)
			} else {
				logInfo("\n[*] Varredura concluída. %d hosts processados, %d achados relevantes encontrados.\n", snapshot.Processed, found)
			}
		}
		logInfo("%s\n", formatScanBreakdown(snapshot))
		if fatalErr != nil {
			return fmt.Errorf("a execução agressiva foi interrompida para impedir novas alterações externas: %w", fatalErr)
		}

		if daemonInterval == 0 {
			break
		}

		actualInterval := daemonInterval
		var latestChange time.Time
		if db.GetDB() != nil {
			err := db.GetDB().QueryRowContext(ctx, "SELECT MAX(last_state_change) FROM hosts WHERE last_state_change IS NOT NULL").Scan(&latestChange)
			if err == nil && !latestChange.IsZero() {
				timeSinceChange := time.Since(latestChange)
				if timeSinceChange < 24*time.Hour {
					// Temp quente! Aceleramos
					actualInterval = daemonInterval / 4
					if actualInterval < 1*time.Minute {
						actualInterval = 1 * time.Minute
					}
					logInfo("[!] Temperatura QUENTE: última mudança ocorreu há %s. Acelerando intervalo para %s.\n", timeSinceChange.Round(time.Minute), actualInterval)
				}
			}
		}

		logInfo("[*] Modo Daemon: aguardando %s até a próxima execução...\n", actualInterval)
		timer := time.NewTimer(actualInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
	return nil
}

func validateAggressiveRuntime(enabled bool, daemonInterval string) error {
	if enabled && strings.TrimSpace(daemonInterval) != "" {
		return fmt.Errorf("--aggressive não pode ser combinado com --daemon; a reivindicação automática exige uma execução única e explícita")
	}
	return nil
}

func enableCheckAllModules() {
	checkNS = true
	checkSRV = true
	checkCloud = true
	checkAXFR = true
	checkDNSSEC = true
	checkEmail = true
	checkHeaders = true
	checkShadowIT = true
	checkRedirects = true
}

func parseSRVOwners(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	seen := make(map[string]struct{})
	var owners []string
	for _, item := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		owner := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(item, ".")))
		parts := strings.Split(owner, ".")
		if len(parts) != 2 || !strings.HasPrefix(parts[0], "_") || (parts[1] != "_tcp" && parts[1] != "_udp") || strings.ContainsAny(owner, "/\\:@*?") {
			return nil, fmt.Errorf("nome proprietário SRV inválido %q; use _service._tcp ou _service._udp", item)
		}
		if _, exists := seen[owner]; !exists {
			seen[owner] = struct{}{}
			owners = append(owners, owner)
		}
	}
	return owners, nil
}

func appendHTTPMutatorIfEnabled(collectors []evidence.Collector, enabled bool, allSignatures []signatures.Fingerprint, timeout time.Duration) []evidence.Collector {
	if !enabled {
		return collectors
	}
	return append(collectors, evidence.NewHTTPMutatorCollector(allSignatures, timeout))
}

func newFramingCollectorIfAuthorized(enabled, controlled bool, rawAllowlist string, timeout time.Duration) (*evidence.HTTPMutatorCollector, error) {
	if !enabled {
		return nil, nil
	}
	if !controlled {
		return nil, fmt.Errorf("--check-framing exige --framing-confirm-controlled")
	}
	authorities, err := parseFramingAllowlist(rawAllowlist)
	if err != nil {
		return nil, err
	}
	return evidence.NewHTTPFramingCollector(timeout, authorities)
}

func parseFramingAllowlist(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("--check-framing exige --framing-allowlist")
	}
	content := raw
	if data, err := os.ReadFile(raw); err == nil {
		content = string(data)
	}
	var authorities []string
	seen := make(map[string]struct{})
	for _, item := range strings.FieldsFunc(content, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		authority := strings.ToLower(strings.TrimSpace(item))
		if authority == "" {
			continue
		}
		if strings.Contains(authority, "://") || strings.ContainsAny(authority, "/\\?#@*") {
			return nil, fmt.Errorf("autoridade inválida na lista permitida: %q", authority)
		}
		if _, exists := seen[authority]; !exists {
			seen[authority] = struct{}{}
			authorities = append(authorities, authority)
		}
	}
	if len(authorities) == 0 {
		return nil, fmt.Errorf("a lista permitida de framing está vazia")
	}
	return authorities, nil
}

func currentScanProfile(cfg *config.Config, signatureDigest string) *core.ScanProfile {
	profile := &core.ScanProfile{
		Version:         1,
		SignatureDigest: signatureDigest,
		CheckNS:         cfg != nil && cfg.CheckNS,
		CheckCloud:      checkCloud,
		CheckAXFR:       checkAXFR,
		CheckDNSSEC:     checkDNSSEC,
		CheckEmail:      checkEmail,
		CheckHeaders:    checkHeaders,
		CheckShadowIT:   checkShadowIT,
		CheckRedirects:  checkRedirects,
		CheckEvasion:    checkEvasion,
		CheckFraming:    checkFraming,
		Aggressive:      aggressive,
		CheckSRV:        checkSRV,
		SRVOwners:       append([]string(nil), configuredSRVOwners...),
		SRVExhaustive:   srvExhaustive,
	}
	if cfg != nil {
		profile.FollowRedirects = cfg.FollowRedirects
		profile.FetchHeaders = cfg.FetchHeaders
		profile.UserAgent = cfg.UserAgent
	}
	return profile
}

func cloneScanProfile(profile *core.ScanProfile) *core.ScanProfile {
	if profile == nil {
		return nil
	}
	clone := *profile
	clone.SRVOwners = append([]string(nil), profile.SRVOwners...)
	return &clone
}

func explicitRootDomains(domains []string) map[string]struct{} {
	roots := make(map[string]struct{})
	for _, domain := range domains {
		root := dns.ExtractRootDomain(domain)
		if root != "" && strings.EqualFold(root, domain) {
			roots[root] = struct{}{}
		}
	}
	return roots
}

func processDomain(
	ctx context.Context,
	domain string,
	registry *evidence.Registry,
	verifierEngine *verifiers.Engine,
	autoClaimer *claimengine.Engine,
	res *dns.Resolver,
	db *storage.Store,
	dispatcher *notify.Dispatcher,
	cfg *config.Config,
	scanProfile *core.ScanProfile,
	explicitRoots map[string]struct{},
	outputDeduper *scanFindingDeduper,
	debugLog *log.Logger,
	outMu *sync.Mutex,
	found *int,
	foundMu *sync.Mutex,
) domainResult {
	select {
	case <-ctx.Done():
		return domainResult{Outcome: domainCanceled}
	default:
	}

	debugLog.Printf("Verificando %s ...", domain)

	dnsRecords, err := res.DiscoverProfile(ctx, domain)
	if err != nil {
		if errors.Is(err, dns.ErrWildcardFiltered) {
			debugLog.Printf("Ignorando %s: resposta idêntica ao wildcard DNS", domain)
			return domainResult{Outcome: domainSkipped}
		}
		if isContextCancellation(ctx, err) {
			return domainResult{Outcome: domainCanceled}
		}
		debugLog.Printf("Erro na descoberta de %s: %v", domain, err)
		return domainResult{Outcome: domainFailed}
	}
	if checkSRV && !strings.HasPrefix(domain, "_") {
		srvBase := dns.ExtractRootDomain(domain)
		if srvExhaustive || srvBase == "" {
			srvBase = domain
		}
		records, discoverErr := res.DiscoverCommonSRV(ctx, srvBase, configuredSRVOwners)
		if discoverErr == nil && len(records) > 0 && outputDeduper.First("SRV_DISCOVERY|"+srvBase) {
			dnsRecords.SRVRecords = mergeSRVRecords(dnsRecords.SRVRecords, records)
			dnsRecords.SRV = dnsRecords.SRV[:0]
			for _, record := range dnsRecords.SRVRecords {
				dnsRecords.SRV = append(dnsRecords.SRV, fmt.Sprintf("%s:%d", record.Target, record.Port))
			}
		}
	}

	analysis := &core.HostAnalysis{
		Host:           domain,
		DNS:            dnsRecords,
		Classification: "UNKNOWN",
		ScanProfile:    cloneScanProfile(scanProfile),
	}
	if analysis.ScanProfile != nil {
		_, analysis.ScanProfile.RelatedImpactInScope = explicitRoots[dns.ExtractRootDomain(domain)]
	}

	if err := registry.Run(ctx, analysis); err != nil {
		if isContextCancellation(ctx, err) {
			return domainResult{Outcome: domainCanceled}
		}
		debugLog.Printf("Erro ao processar evidências para %s: %v", domain, err)
		return domainResult{Outcome: domainFailed}
	}

	if len(analysis.DNS.A) == 0 && len(analysis.DNS.CNAME) == 0 && len(analysis.DNS.MX) == 0 && len(analysis.DNS.SRV) == 0 && len(analysis.Evidences) == 0 {
		return domainResult{Outcome: domainSkipped}
	}

	classification.Process(analysis)

	verifierEngine.Run(ctx, analysis)
	if analysis.VerificationScore > 0 {
		// Reavaliação para promoção a CONFIRMED_TAKEOVERABLE
		analysis.Classification = classification.Classify(analysis)
	}
	var fatalClaimErr error
	if autoClaimer != nil {
		if err := autoClaimer.Execute(ctx, analysis); err != nil {
			debugLog.Printf("A reivindicação automática de %s terminou com erro: %v", domain, err)
			if errors.Is(err, claimengine.ErrUnsafeClaimState) {
				fatalClaimErr = err
			}
		}
		analysis.Classification = classification.Classify(analysis)
	}
	if ctx.Err() != nil {
		return domainResult{Outcome: domainCanceled}
	}
	verdict := confidence.Calculate(analysis)

	if err := db.SaveAnalysis(analysis); err != nil {
		if isContextCancellation(ctx, err) {
			return domainResult{Outcome: domainCanceled}
		}
		debugLog.Printf("Erro ao salvar no BD para %s: %v", domain, err)
		if fatalClaimErr != nil {
			return domainResult{Outcome: domainFailed, FatalErr: errors.Join(fatalClaimErr, fmt.Errorf("persistindo a análise de %s: %w", domain, err))}
		}
		return domainResult{Outcome: domainFailed}
	}
	dispatcher.DispatchAnalysis(analysis)

	suppressDelegation := false
	if analysis.Delegation != nil && hasDelegationFinding(analysis) {
		suppressDelegation = !outputDeduper.First("NS|" + analysis.Delegation.Zone)
	}
	relevant := isActionableClassification(analysis.Classification)
	visible := relevant && cliSeverityAllows(analysis.Classification, scanMinSeverity)
	countable := visible && !(suppressDelegation && isDelegationClassification(analysis.Classification))

	foundMu.Lock()
	if countable {
		(*found)++
	}
	foundMu.Unlock()

	outMu.Lock()
	useColor := !cfg.NoColor && color.Enabled(os.Stdout)
	if scanQuiet {
		if countable {
			fmt.Println(analysis.Host)
		}
	} else if cfg.JSONOutput {
		data, _ := json.Marshal(analysis)
		fmt.Println(string(data))
	} else if scanExplainJ {
		type ExplainOutput struct {
			Host            string          `json:"host"`
			Classification  string          `json:"classification"`
			RiskScore       int             `json:"risk_score"`
			MitigationScore int             `json:"mitigation_score"`
			ConfidenceScore int             `json:"confidence_score"`
			Positive        []core.Evidence `json:"positive_evidences"`
			Negative        []core.Evidence `json:"negative_evidences"`
		}
		out := ExplainOutput{
			Host:            analysis.Host,
			Classification:  analysis.Classification,
			RiskScore:       analysis.RiskScore,
			MitigationScore: analysis.MitigationScore,
			ConfidenceScore: analysis.ConfidenceScore,
		}
		for _, ev := range analysis.Evidences {
			if ev.IsNegative {
				out.Negative = append(out.Negative, ev)
			} else {
				out.Positive = append(out.Positive, ev)
			}
		}
		data, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(data))
	} else if scanExplain {
		fmt.Printf("\n========================================\n")
		fmt.Printf("MODO DE EXPLICAÇÃO: %s\n", analysis.Host)
		fmt.Printf("========================================\n")
		fmt.Printf("%s — Confiança: %s\n\n",
			color.ColorizeClassificationLabelWith(analysis.Classification, presentation.Classification(analysis.Classification), useColor),
			verdict.Label,
		)

		fmt.Printf("Pontuação de cobertura    : %.1f%%\n", analysis.CoverageScore)
		fmt.Printf("Pontuação de conhecimento : %.1f%%\n", analysis.KnowledgeScore)
		fmt.Printf("Confiança                  : %s\n\n", verdict.Label)

		known := make(map[string]bool)
		for _, ev := range analysis.Evidences {
			if strings.Contains(ev.Type, "PROVIDER_MATCH") && ev.Type != "CLOUD_PROVIDER_MATCH" && ev.Type != "ASN_PROVIDER_MATCH" {
				known[ev.Source] = true
			}
		}

		fmt.Printf("Provedores conhecidos:\n")
		if len(known) > 0 {
			for k := range known {
				fmt.Printf("  - %s\n", k)
			}
		} else {
			fmt.Printf("  (nenhum)\n")
		}
		fmt.Println()

		fmt.Printf("Provedores desconhecidos:\n")
		if analysis.UnknownProvider != nil {
			fmt.Printf("  - %s (severidade %s)\n",
				analysis.UnknownProvider.RootDomain,
				presentation.Severity(analysis.UnknownProvider.Severity),
			)
		} else {
			fmt.Printf("  (nenhum)\n")
		}
		fmt.Println()

		fmt.Printf("Alertas e motivos:\n")
		if len(verdict.Reasons) > 0 {
			for _, r := range verdict.Reasons {
				fmt.Printf("  - %s\n", r)
			}
		} else {
			fmt.Printf("  (nenhum)\n")
		}

		if analysis.VerificationScore > 0 && analysis.ActiveVerification != nil {
			fmt.Printf("\nCamada de verificação:\n")
			fmt.Printf("  Provedor: %s\n", analysis.ActiveVerification.Provider)
			fmt.Printf("  Resultado: %s\n", presentation.Classification(analysis.Classification))
		}

		fmt.Printf("\nPontuações brutas:\n")
		fmt.Printf("  Risco: %d\n  Mitigação: %d\n  Confiança-base: %d\n", analysis.RiskScore, analysis.MitigationScore, analysis.ConfidenceScore)
		fmt.Printf("========================================\n\n")
	} else if visible || scanShowInconclusive {
		fmt.Print(report.HumanWithOptions(analysis, verdict.Label, report.Options{
			Color: useColor, SuppressDelegation: suppressDelegation,
		}))
	}
	outMu.Unlock()

	outcome := domainCompleted
	if fatalClaimErr != nil {
		outcome = domainFailed
	}
	return domainResult{
		Outcome:        outcome,
		Classification: analysis.Classification,
		Actionable:     countable,
		FatalErr:       fatalClaimErr,
	}
}

func effectiveHostConcurrency(requested, operationsPerSecond int) int {
	if requested < 1 {
		requested = 1
	}
	if operationsPerSecond > 0 && requested > operationsPerSecond {
		return operationsPerSecond
	}
	return requested
}

func validateScanOutputModes(cfg *config.Config) error {
	var modes []string
	if scanQuiet {
		modes = append(modes, "--quiet")
	}
	if cfg != nil && cfg.JSONOutput {
		modes = append(modes, "--json")
	}
	if scanExplain {
		modes = append(modes, "--explain")
	}
	if scanExplainJ {
		modes = append(modes, "--explain-json")
	}
	if len(modes) > 1 {
		return fmt.Errorf("modos de saída incompatíveis: %s; escolha apenas um", strings.Join(modes, ", "))
	}
	if scanShowInconclusive && scanQuiet {
		return fmt.Errorf("--show-inconclusive não pode ser combinado com --quiet")
	}
	return nil
}

func isContextCancellation(ctx context.Context, err error) bool {
	return ctx.Err() != nil || errors.Is(err, context.Canceled)
}

type scanFindingDeduper struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

func newScanFindingDeduper() *scanFindingDeduper {
	return &scanFindingDeduper{seen: make(map[string]struct{})}
}

func (deduper *scanFindingDeduper) First(key string) bool {
	if deduper == nil {
		return true
	}
	key = strings.ToLower(strings.TrimSpace(key))
	deduper.mu.Lock()
	defer deduper.mu.Unlock()
	if _, exists := deduper.seen[key]; exists {
		return false
	}
	deduper.seen[key] = struct{}{}
	return true
}

func isDelegationClassification(level string) bool {
	switch level {
	case classification.LevelDelegationBroken, classification.LevelDelegationTakeoverCandidate,
		classification.LevelDelegationClaimabilityVerified, classification.LevelZoneControlConfirmed:
		return true
	default:
		return false
	}
}

func isActionableClassification(level string) bool {
	return level != "" &&
		level != classification.LevelHealthy &&
		level != classification.LevelUnknown &&
		level != classification.LevelInsufficientEvidence
}

func cliSeverityAllows(level, minimum string) bool {
	if strings.TrimSpace(minimum) == "" {
		return true
	}
	minimumSeverity, err := notify.ParseSeverity(minimum)
	if err != nil {
		return false
	}
	current := notify.ClassificationSeverity(level)
	return notify.SeverityRank(current) >= notify.SeverityRank(minimumSeverity)
}

func hasDelegationFinding(analysis *core.HostAnalysis) bool {
	if analysis == nil {
		return false
	}
	for _, evidence := range analysis.Evidences {
		switch evidence.Type {
		case "DELEGATION_BROKEN", "DELEGATION_TAKEOVER_CANDIDATE",
			"DELEGATION_CLAIMABILITY_VERIFIED", "DELEGATION_CLAIMABILITY_NOT_DEMONSTRATED",
			"ZONE_CONTROL_CONFIRMED":
			return true
		}
	}
	return false
}

func mergeSRVRecords(groups ...[]core.SRVRecord) []core.SRVRecord {
	seen := make(map[string]struct{})
	var merged []core.SRVRecord
	for _, records := range groups {
		for _, record := range records {
			key := fmt.Sprintf("%s|%s|%d|%d|%d", record.Owner, record.Target, record.Port, record.Priority, record.Weight)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			merged = append(merged, record)
		}
	}
	return merged
}
