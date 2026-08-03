package dns

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/sync/singleflight"
)

const (
	// maxChainDepth limita a profundidade da resolução recursiva de CNAMEs
	// para evitar ciclos infinitos ou cadeias excessivamente longas.
	maxChainDepth = 10

	// maxRetries define o número máximo de tentativas para uma consulta DNS.
	maxRetries = 3

	// baseRetryDelay é o atraso base para a espera exponencial (100ms → 300ms → 900ms).
	baseRetryDelay = 100 * time.Millisecond

	// maxDoHResponseSize é o maior tamanho possível de uma mensagem DNS
	// transportada por TCP ou HTTPS, conforme o campo de tamanho de 16 bits.
	maxDoHResponseSize = 65535
)

// defaultServers contém os resolvedores DNS públicos usados quando nenhum
// servidor personalizado é fornecido pela flag -r.
var defaultServers = []string{
	"1.1.1.1:53", // Cloudflare
	"8.8.8.8:53", // Google
	"9.9.9.9:53", // Quad9
	"8.8.4.4:53", // Google secundário
}

var ErrWildcardFiltered = errors.New("a resposta do host é indistinguível do wildcard DNS")

// Resolver realiza consultas DNS diretas via UDP usando miekg/dns, com suporte
// a um conjunto de servidores (alternância circular), novas tentativas com
// espera exponencial, resolução recursiva de cadeias CNAME, detecção de registros
// DNS curingas e consulta de NS.
type Resolver struct {
	client  *dns.Client
	servers []string
	index   uint64 // índice atômico para round-robin

	wildcardCache   sync.Map
	queryCache      sync.Map
	zoneCache       sync.Map
	nsHealthCache   sync.Map
	axfrCache       sync.Map
	dnssecCache     sync.Map
	queryGroup      singleflight.Group
	zoneGroup       singleflight.Group
	nsHealthGroup   singleflight.Group
	axfrGroup       singleflight.Group
	dnssecGroup     singleflight.Group
	dohURL          string
	dohClient       *http.Client
	serverConfigErr error
	filterWildcard  bool
	limiter         interface{ Wait(context.Context) error }
	timeout         time.Duration
}

// SetDoH define a URL do resolver DoH (ex.: https://1.1.1.1/dns-query).
func (r *Resolver) SetDoH(url string) {
	r.dohURL = strings.TrimSpace(url)
}

// SetDoHClient define o cliente HTTP usado pelo transporte DoH. O chamador
// pode, assim, aplicar o mesmo proxy da varredura sem duplicar o limitador DNS.
func (r *Resolver) SetDoHClient(client *http.Client) {
	if client != nil {
		r.dohClient = client
	}
}

func (r *Resolver) SetWildcardFiltering(enabled bool) {
	r.filterWildcard = enabled
}

func (r *Resolver) SetRequestLimiter(limiter interface{ Wait(context.Context) error }) {
	r.limiter = limiter
}

// SetTimeout configura o orçamento de rede usado depois que o resolvedor obtém uma
// permissão do limitador de taxa, incluindo tráfego recursivo, autoritativo, DoH e AXFR.
func (r *Resolver) SetTimeout(timeout time.Duration) {
	if timeout <= 0 {
		return
	}
	r.timeout = timeout
	r.client.Timeout = timeout
}

func (r *Resolver) wait(ctx context.Context) error {
	if r.limiter == nil {
		return nil
	}
	return r.limiter.Wait(ctx)
}

// ClearCache limpa o cache de DNS mantido em memória.
func (r *Resolver) ClearCache() {
	r.queryCache = sync.Map{}
	r.wildcardCache = sync.Map{}
	r.zoneCache = sync.Map{}
	r.nsHealthCache = sync.Map{}
	r.axfrCache = sync.Map{}
	r.dnssecCache = sync.Map{}
}

// wildcardResult armazena o resultado em cache de uma verificação de registro DNS curinga.
type wildcardResult struct {
	isWildcard bool
	signature  WildcardSignature
}

// WildcardSignature preserva os RRsets por tipo. Isso evita confundir um host
// explícito com o curinga quando CNAME e endereços aparecem na mesma resposta.
type WildcardSignature struct {
	A     []string
	AAAA  []string
	CNAME []string
}

func (signature WildcardSignature) Empty() bool {
	return len(signature.A) == 0 && len(signature.AAAA) == 0 && len(signature.CNAME) == 0
}

func (signature WildcardSignature) MatchesA(values []string) bool {
	return len(signature.A) > 0 && equalRRSet(signature.A, values)
}

func (signature WildcardSignature) MatchesAAAA(values []string) bool {
	return len(signature.AAAA) > 0 && equalRRSet(signature.AAAA, values)
}

func (signature WildcardSignature) MatchesCNAME(values []string) bool {
	return len(signature.CNAME) > 0 && equalRRSet(signature.CNAME, values)
}

// wildcardLock armazena o mutex para coordenar as requisições de um domínio
type wildcardLock struct {
	mu     sync.Mutex
	result *wildcardResult // nil enquanto estiver pendente/consultando
}

// New cria um Resolver com um conjunto de servidores DNS. Se servers for nil ou
// vazio, usa os resolvedores públicos padrão (Cloudflare, Google, Quad9).
// Servidores sem porta recebem ":53" automaticamente.
func New(servers []string) *Resolver {
	if len(servers) == 0 {
		servers = defaultServers
	}

	normalizedServers := make([]string, 0, len(servers))
	var serverConfigErr error
	for index, server := range servers {
		endpoint, err := normalizeResolverEndpoint(server)
		if err != nil {
			if serverConfigErr == nil {
				serverConfigErr = fmt.Errorf("resolver %d: %w", index+1, err)
			}
			continue
		}
		normalizedServers = append(normalizedServers, endpoint)
	}

	return &Resolver{
		client: &dns.Client{
			Timeout:        5 * time.Second,
			Net:            "udp",
			SingleInflight: true,
		},
		servers:         normalizedServers,
		dohClient:       newDoHHTTPClient(),
		serverConfigErr: serverConfigErr,
		filterWildcard:  true,
		timeout:         5 * time.Second,
	}
}

// LoadResolversFromFile carrega uma lista de servidores DNS de um arquivo de texto.
// Formato: um IP ou IP:porta por linha. Linhas vazias e comentários (#) são ignorados.
func LoadResolversFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("abrindo arquivo de resolvedores %q: %w", path, err)
	}
	defer f.Close()

	var servers []string
	scanner := bufio.NewScanner(f)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		endpoint, normalizeErr := normalizeResolverEndpoint(line)
		if normalizeErr != nil {
			return nil, fmt.Errorf("resolvedor inválido na linha %d: %w", lineNumber, normalizeErr)
		}
		servers = append(servers, endpoint)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("lendo arquivo de resolvedores: %w", err)
	}

	if len(servers) == 0 {
		return nil, fmt.Errorf("arquivo de resolvedores %q está vazio ou contém apenas comentários", path)
	}

	return servers, nil
}

// pickServer retorna atomicamente o próximo servidor DNS por alternância circular.
// É seguro para uso concorrente por múltiplas rotinas de trabalho.
func (r *Resolver) pickServer() string {
	idx := atomic.AddUint64(&r.index, 1) - 1
	return r.servers[idx%uint64(len(r.servers))]
}

// exchange envia uma mensagem DNS para um servidor com novas tentativas e espera exponencial.
// Retenta apenas em erros de rede/timeout, nunca em respostas DNS válidas
// (mesmo NXDOMAIN ou SERVFAIL são respostas legítimas do protocolo).
func (r *Resolver) exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	cacheKey := dnsQueryCacheKey(msg)
	if cacheKey == "" {
		return r.exchangeUncached(ctx, msg)
	}
	if cached, ok := r.queryCache.Load(cacheKey); ok {
		return cached.(*dns.Msg).Copy(), nil
	}

	value, err, _ := r.queryGroup.Do(cacheKey, func() (interface{}, error) {
		if cached, ok := r.queryCache.Load(cacheKey); ok {
			return cached.(*dns.Msg).Copy(), nil
		}
		response, exchangeErr := r.exchangeUncached(ctx, msg)
		if exchangeErr != nil {
			return nil, exchangeErr
		}
		if cacheableDNSResponse(response) {
			r.queryCache.Store(cacheKey, response.Copy())
		}
		return response, nil
	})
	if err != nil {
		return nil, err
	}
	if value == nil {
		return nil, nil
	}
	return value.(*dns.Msg).Copy(), nil
}

func cacheableDNSResponse(response *dns.Msg) bool {
	return response != nil &&
		(response.Rcode == dns.RcodeSuccess || response.Rcode == dns.RcodeNameError)
}

func (r *Resolver) exchangeUncached(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if r.dohURL != "" {
		return r.exchangeDoH(ctx, msg)
	}
	if r.serverConfigErr != nil {
		return nil, fmt.Errorf("configuração dos resolvedores inválida: %w", r.serverConfigErr)
	}
	if len(r.servers) == 0 {
		return nil, fmt.Errorf("nenhum resolver DNS válido foi configurado")
	}
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		server := r.pickServer()

		if err := r.wait(ctx); err != nil {
			return nil, err
		}
		resp, _, err := r.client.ExchangeContext(ctx, msg, server)
		if err == nil {
			if resp != nil && resp.Truncated {
				// Repete a consulta por TCP quando a resposta UDP é truncada.
				tcpClient := &dns.Client{Net: "tcp", Timeout: r.client.Timeout}
				if err := r.wait(ctx); err != nil {
					return nil, err
				}
				respTCP, _, errTCP := tcpClient.ExchangeContext(ctx, msg, server)
				if errTCP == nil {
					resp = respTCP
				}
			}
			return resp, nil
		}

		lastErr = err

		// Repete somente erros transitórios de rede ou tempo limite.
		var netErr net.Error
		if !isNetError(err, &netErr) {
			// Contexto cancelado e outros erros definitivos encerram a consulta.
			return nil, err
		}

		// Espera exponencial: 100ms, 300ms, 900ms
		if attempt < maxRetries-1 {
			delay := baseRetryDelay
			for i := 0; i < attempt; i++ {
				delay *= 3
			}

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}
	}

	return nil, fmt.Errorf("consulta DNS falhou após %d tentativas: %w", maxRetries, lastErr)
}

func (r *Resolver) exchangeDoH(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	wire, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("codificando consulta DoH: %w", err)
	}

	if err := r.wait(ctx); err != nil {
		return nil, fmt.Errorf("aguardando permissão para a consulta DoH: %w", err)
	}
	networkContext, cancel := context.WithTimeout(ctx, r.operationTimeout())
	defer cancel()

	req, err := http.NewRequestWithContext(networkContext, http.MethodPost, r.dohURL, bytes.NewReader(wire))
	if err != nil {
		return nil, fmt.Errorf("criando requisição DoH: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	client := r.dohClient
	if client == nil {
		client = newDoHHTTPClient()
	}
	respHTTP, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executando consulta DoH: %w", err)
	}
	defer respHTTP.Body.Close()

	if respHTTP.StatusCode >= http.StatusMultipleChoices && respHTTP.StatusCode < http.StatusBadRequest {
		return nil, fmt.Errorf("o endpoint DoH respondeu com redirecionamento HTTP %d; configure a URL final", respHTTP.StatusCode)
	}
	if respHTTP.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("o endpoint DoH respondeu com status HTTP %d", respHTTP.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(respHTTP.Body, maxDoHResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("lendo resposta DoH: %w", err)
	}
	if len(body) > maxDoHResponseSize {
		return nil, fmt.Errorf("a resposta DoH excede o limite de %d bytes", maxDoHResponseSize)
	}

	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(body); err != nil {
		return nil, fmt.Errorf("decodificando resposta DoH: %w", err)
	}

	return respMsg, nil
}

func newDoHHTTPClient() *http.Client {
	return &http.Client{
		Transport: http.DefaultTransport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func normalizeResolverEndpoint(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("endereço vazio")
	}

	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		host := strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
		if ip := net.ParseIP(host); ip != nil {
			return net.JoinHostPort(ip.String(), "53"), nil
		}
		return "", fmt.Errorf("endereço IPv6 entre colchetes inválido: %q", value)
	}

	if host, port, err := net.SplitHostPort(value); err == nil {
		if host == "" {
			return "", fmt.Errorf("host ausente em %q", value)
		}
		portNumber, parseErr := strconv.Atoi(port)
		if parseErr != nil || portNumber < 1 || portNumber > 65535 {
			return "", fmt.Errorf("porta DNS inválida em %q", value)
		}
		if ip := net.ParseIP(host); ip != nil {
			host = ip.String()
		} else {
			host = strings.TrimSuffix(strings.ToLower(host), ".")
			if host == "" {
				return "", fmt.Errorf("host ausente em %q", value)
			}
		}
		return net.JoinHostPort(host, strconv.Itoa(portNumber)), nil
	}

	if strings.HasPrefix(value, "[") || strings.HasSuffix(value, "]") {
		return "", fmt.Errorf("endpoint DNS inválido: %q", value)
	}
	if ip := net.ParseIP(value); ip != nil {
		return net.JoinHostPort(ip.String(), "53"), nil
	}
	if strings.Contains(value, ":") {
		return "", fmt.Errorf("endpoint DNS inválido %q; use [IPv6]:porta quando informar uma porta", value)
	}

	host := strings.TrimSuffix(strings.ToLower(value), ".")
	if host == "" {
		return "", fmt.Errorf("host vazio")
	}
	if _, valid := dns.IsDomainName(host); !valid {
		return "", fmt.Errorf("host DNS inválido: %q", value)
	}
	return net.JoinHostPort(host, "53"), nil
}

func (r *Resolver) operationTimeout() time.Duration {
	if r.timeout > 0 {
		return r.timeout
	}
	if r.client != nil && r.client.Timeout > 0 {
		return r.client.Timeout
	}
	return 5 * time.Second
}

func dnsQueryCacheKey(msg *dns.Msg) string {
	if msg == nil || len(msg.Question) == 0 {
		return ""
	}
	question := msg.Question[0]
	doBit := false
	if option := msg.IsEdns0(); option != nil {
		doBit = option.Do()
	}
	return fmt.Sprintf(
		"%d:%d:%s:rd=%t:cd=%t:do=%t",
		question.Qclass,
		question.Qtype,
		strings.ToLower(question.Name),
		msg.RecursionDesired,
		msg.CheckingDisabled,
		doBit,
	)
}

// isNetError verifica se o erro é um erro de rede retentável.
func isNetError(err error, target *net.Error) bool {
	var nerr net.Error
	if errors.As(err, &nerr) {
		*target = nerr
		return true
	}
	return false
}

// ResolveCNAME retorna todos os alvos CNAME de um dado domínio em uma única consulta.
// Primeiro consulta TypeCNAME e depois usa TypeA como alternativa (resolvedores
// recursivos frequentemente incluem registros CNAME na resposta de consultas A).
// Retorna nil, nil se nenhum registro CNAME for encontrado (não é um erro).
func (r *Resolver) ResolveCNAME(ctx context.Context, domain string) ([]string, error) {
	fqdn := dns.Fqdn(domain)

	for _, qtype := range []uint16{dns.TypeCNAME, dns.TypeA} {
		m := new(dns.Msg)
		m.SetQuestion(fqdn, qtype)
		m.RecursionDesired = true

		resp, err := r.exchange(ctx, m)
		if err != nil {
			continue
		}

		var cnames []string
		for _, ans := range resp.Answer {
			if cn, ok := ans.(*dns.CNAME); ok {
				target := strings.TrimSuffix(strings.ToLower(cn.Target), ".")
				cnames = append(cnames, target)
			}
		}
		if len(cnames) > 0 {
			return cnames, nil
		}
	}

	return nil, nil
}

// ResolveCNAMEChain segue a cadeia de CNAMEs recursivamente até a profundidade
// máxima (10) ou até que não haja mais CNAMEs. Retorna a cadeia ordenada:
// [cname1, cname2, ..., cname_final].
//
// A cadeia completa permite avaliar destinos após vários saltos:
//
//	dev.alvo.com → cname1.alvo.com → app.herokuapp.com
//
// Onde apenas o último CNAME é vulnerável.
func (r *Resolver) ResolveCNAMEChain(ctx context.Context, domain string) ([]string, error) {
	var chain []string
	current := domain
	seen := make(map[string]bool) // Detecta ciclos.

	for depth := 0; depth < maxChainDepth; depth++ {
		select {
		case <-ctx.Done():
			return chain, ctx.Err()
		default:
		}

		fqdn := dns.Fqdn(current)

		// Interrompe ciclos na cadeia.
		if seen[fqdn] {
			break
		}
		seen[fqdn] = true

		m := new(dns.Msg)
		m.SetQuestion(fqdn, dns.TypeCNAME)
		m.RecursionDesired = true

		resp, err := r.exchange(ctx, m)
		if err != nil {
			// Preserva os saltos obtidos antes de uma falha intermediária.
			if len(chain) > 0 {
				return chain, nil
			}
			return nil, err
		}

		// Continua pelo primeiro CNAME da resposta.
		var nextCNAME string
		for _, ans := range resp.Answer {
			if cn, ok := ans.(*dns.CNAME); ok {
				nextCNAME = strings.TrimSuffix(strings.ToLower(cn.Target), ".")
				break
			}
		}

		if nextCNAME == "" {
			// Sem outro CNAME, tenta TypeA como alternativa apenas na primeira consulta.
			if len(chain) == 0 {
				return r.resolveCNAMEViaA(ctx, domain)
			}
			break
		}

		chain = append(chain, nextCNAME)
		current = nextCNAME
	}

	return chain, nil
}

// ResolveMX retorna a lista de servidores de e-mail configurados (MX) para o domínio.
// É usado para detectar takeover via MX.
func (r *Resolver) ResolveMX(ctx context.Context, fqdn string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeMX)
	m.RecursionDesired = true

	resp, err := r.exchange(ctx, m)
	if err != nil {
		return nil, fmt.Errorf("falha ao resolver MX: %w", err)
	}

	var mxs []string
	if resp.Rcode == dns.RcodeSuccess {
		for _, ans := range resp.Answer {
			if mx, ok := ans.(*dns.MX); ok {
				if mx.Preference == 0 && strings.TrimSpace(mx.Mx) == "." {
					mxs = append(mxs, ".")
					continue
				}
				target := strings.TrimSuffix(strings.ToLower(mx.Mx), ".")
				if target != "" {
					mxs = append(mxs, target)
				}
			}
		}
	}
	return mxs, nil
}

// ResolveA retorna os endereços IPv4 (A) configurados para o domínio.
func (r *Resolver) ResolveA(ctx context.Context, fqdn string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
	m.RecursionDesired = true

	resp, err := r.exchange(ctx, m)
	if err != nil {
		return nil, fmt.Errorf("falha ao resolver A: %w", err)
	}

	var ips []string
	if resp.Rcode == dns.RcodeSuccess {
		for _, ans := range resp.Answer {
			if a, ok := ans.(*dns.A); ok {
				ips = append(ips, a.A.String())
			}
		}
	}
	return ips, nil
}

// resolveCNAMEViaA tenta extrair CNAMEs da seção de resposta de uma consulta TypeA.
// Resolvers recursivos frequentemente incluem toda a cadeia CNAME na resposta de A.
func (r *Resolver) resolveCNAMEViaA(ctx context.Context, domain string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.RecursionDesired = true

	resp, err := r.exchange(ctx, m)
	if err != nil {
		return nil, nil // sem CNAMEs, não é um erro
	}

	var cnames []string
	for _, ans := range resp.Answer {
		if cn, ok := ans.(*dns.CNAME); ok {
			target := strings.TrimSuffix(strings.ToLower(cn.Target), ".")
			cnames = append(cnames, target)
		}
	}

	return cnames, nil
}

// CheckNXDomain verifica se um domínio resolve para NXDOMAIN (domínio inexistente).
// Usado para serviços onde o takeover é detectado via CNAME pendente apontando para
// um alvo inexistente (ex.: AWS Elastic Beanstalk).
// Usa novas tentativas com espera exponencial e alternância circular de servidores.
func (r *Resolver) CheckNXDomain(ctx context.Context, domain string) (bool, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.RecursionDesired = true

	resp, err := r.exchange(ctx, m)
	if err != nil {
		return false, fmt.Errorf("verificação NXDOMAIN para %s: %w", domain, err)
	}

	// dns.RcodeNameError == NXDOMAIN (rcode 3)
	return resp.Rcode == dns.RcodeNameError, nil
}

// IsWildcard verifica se um domínio raiz possui registro DNS curinga.
// Gera dois subdomínios aleatórios inexistentes e exige RRsets idênticos por
// tipo para reduzir falsos positivos causados por registros explícitos.
// Resultados são cacheados por domínio raiz para evitar consultas redundantes.
//
// Retorna:
//   - (true, assinatura, nil) quando ambas as sondas produzem os mesmos RRsets;
//   - (false, assinatura vazia, nil) quando não há curinga reproduzível;
//   - (false, assinatura vazia, err) quando a consulta é inconclusiva.
func (r *Resolver) IsWildcard(ctx context.Context, fqdn string) (bool, WildcardSignature, error) {
	fqdn = strings.TrimSuffix(strings.ToLower(fqdn), ".")
	parts := strings.Split(fqdn, ".")
	rootDomain, rootErr := publicsuffix.EffectiveTLDPlusOne(fqdn)
	if rootErr != nil || rootDomain == "" {
		return r.checkSingleWildcard(ctx, fqdn)
	}
	rootLabels := strings.Split(rootDomain, ".")
	parents := len(parts) - len(rootLabels)
	if parents <= 0 {
		return r.checkSingleWildcard(ctx, rootDomain)
	}
	for i := 1; i <= parents; i++ {
		parentDomain := strings.Join(parts[i:], ".")
		isWild, signature, err := r.checkSingleWildcard(ctx, parentDomain)
		if err != nil {
			return false, WildcardSignature{}, err
		}
		if isWild {
			return true, signature, nil
		}
	}
	return false, WildcardSignature{}, nil
}

// checkSingleWildcard verifica um domínio e evita consultas concorrentes duplicadas.
func (r *Resolver) checkSingleWildcard(ctx context.Context, domain string) (bool, WildcardSignature, error) {
	// Obtém o bloqueio associado ao domínio.
	val, _ := r.wildcardCache.LoadOrStore(domain, &wildcardLock{})
	lock := val.(*wildcardLock)

	lock.mu.Lock()
	defer lock.mu.Unlock()

	// Reutiliza o resultado preenchido enquanto a rotina aguardava o bloqueio.
	if lock.result != nil {
		return lock.result.isWildcard, cloneWildcardSignature(lock.result.signature), nil
	}

	first, err := r.randomWildcardSignature(ctx, domain)
	if err != nil {
		return false, WildcardSignature{}, err
	}
	second, err := r.randomWildcardSignature(ctx, domain)
	if err != nil {
		return false, WildcardSignature{}, err
	}
	isWild := !first.Empty() && equalWildcardSignature(first, second)
	if !isWild {
		first = WildcardSignature{}
	}

	// Guarda o resultado para as próximas consultas do domínio.
	lock.result = &wildcardResult{
		isWildcard: isWild,
		signature:  cloneWildcardSignature(first),
	}

	return isWild, first, nil
}

func (r *Resolver) randomWildcardSignature(ctx context.Context, domain string) (WildcardSignature, error) {
	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		return WildcardSignature{}, fmt.Errorf("gerando nome aleatório para a verificação de curinga: %w", err)
	}
	owner := dns.Fqdn(hex.EncodeToString(randomBytes) + "." + domain)
	var signature WildcardSignature
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		message := new(dns.Msg)
		message.SetQuestion(owner, qtype)
		message.RecursionDesired = true
		response, err := r.exchange(ctx, message)
		if err != nil {
			return WildcardSignature{}, fmt.Errorf("consultando possível curinga %s: %w", owner, err)
		}
		if response.Rcode != dns.RcodeSuccess {
			continue
		}
		for _, answer := range response.Answer {
			switch record := answer.(type) {
			case *dns.CNAME:
				signature.CNAME = append(signature.CNAME, record.Target)
			case *dns.A:
				signature.A = append(signature.A, record.A.String())
			case *dns.AAAA:
				signature.AAAA = append(signature.AAAA, record.AAAA.String())
			}
		}
	}
	return normalizeWildcardSignature(signature), nil
}

func normalizeWildcardSignature(signature WildcardSignature) WildcardSignature {
	signature.A = normalizeRRSet(signature.A)
	signature.AAAA = normalizeRRSet(signature.AAAA)
	signature.CNAME = normalizeRRSet(signature.CNAME)
	return signature
}

func normalizeRRSet(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		normalized := normalizeDNSName(value)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	sort.Strings(result)
	return result
}

func equalRRSet(left, right []string) bool {
	left, right = normalizeRRSet(left), normalizeRRSet(right)
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalWildcardSignature(left, right WildcardSignature) bool {
	return equalRRSet(left.A, right.A) && equalRRSet(left.AAAA, right.AAAA) && equalRRSet(left.CNAME, right.CNAME)
}

func cloneWildcardSignature(signature WildcardSignature) WildcardSignature {
	return WildcardSignature{
		A: append([]string(nil), signature.A...), AAAA: append([]string(nil), signature.AAAA...),
		CNAME: append([]string(nil), signature.CNAME...),
	}
}

// ExtractRootDomain extrai o domínio registrável usando a Public Suffix List.
// Se o valor não for registrável, retorna a entrada normalizada.
func ExtractRootDomain(fqdn string) string {
	normalized := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fqdn), "."))
	registrable, err := publicsuffix.EffectiveTLDPlusOne(normalized)
	if err != nil {
		return normalized
	}
	return registrable
}

// LookupNS retorna os nomes dos servidores autoritativos de um domínio.
// Útil para detectar takeover via NS (servidores de nomes apontando para zonas removidas).
func (r *Resolver) LookupNS(ctx context.Context, domain string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	m.RecursionDesired = true

	resp, err := r.exchange(ctx, m)
	if err != nil {
		return nil, fmt.Errorf("consulta NS para %s: %w", domain, err)
	}

	var nameservers []string
	for _, ans := range resp.Answer {
		if ns, ok := ans.(*dns.NS); ok {
			nsHost := strings.TrimSuffix(strings.ToLower(ns.Ns), ".")
			nameservers = append(nameservers, nsHost)
		}
	}

	return nameservers, nil
}

// CheckNSHealth verifica se um servidor de nomes responde corretamente para
// um domínio. Envia uma consulta SOA diretamente para o NS e analisa a resposta.
//
// Retorna o status do NS em formato string:
//   - "HEALTHY": NS respondeu normalmente
//   - "REFUSED", "SERVFAIL": falha autoritativa ou configuração incorreta;
//     isoladamente, esses estados não comprovam takeover;
//   - "TIMEOUT" ou "ERROR": problemas de rede ou resolução.
func (r *Resolver) CheckNSHealth(ctx context.Context, nsServer, domain string) (string, error) {
	key := normalizeDNSName(domain) + "|" + normalizeDNSName(nsServer)
	if cached, ok := r.nsHealthCache.Load(key); ok {
		result := cached.(nsHealthResult)
		return result.status, result.err
	}
	value, err, _ := r.nsHealthGroup.Do(key, func() (interface{}, error) {
		if cached, ok := r.nsHealthCache.Load(key); ok {
			return cached.(nsHealthResult), nil
		}
		status, healthErr := r.checkNSHealthUncached(ctx, nsServer, domain)
		result := nsHealthResult{status: status, err: healthErr}
		if !errors.Is(healthErr, context.Canceled) && !errors.Is(healthErr, context.DeadlineExceeded) {
			r.nsHealthCache.Store(key, result)
		}
		return result, nil
	})
	if err != nil {
		return "ERROR", err
	}
	result := value.(nsHealthResult)
	return result.status, result.err
}

type nsHealthResult struct {
	status string
	err    error
}

func (r *Resolver) checkNSHealthUncached(ctx context.Context, nsServer, domain string) (string, error) {
	endpoint, endpointErr := r.nameserverEndpoint(ctx, nsServer)
	if endpointErr != nil {
		return "ERROR", endpointErr
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)
	m.RecursionDesired = false

	nsClient := &dns.Client{
		Timeout: r.operationTimeout(),
		Net:     "udp",
	}

	if err := r.wait(ctx); err != nil {
		return "ERROR", err
	}
	resp, _, err := nsClient.ExchangeContext(ctx, m, endpoint)
	if err != nil {
		var netErr net.Error
		if isNetError(err, &netErr) && netErr.Timeout() {
			return "TIMEOUT", nil
		}
		return "ERROR", fmt.Errorf("contatando NS: %w", err)
	}

	if resp.Rcode == dns.RcodeRefused {
		return "REFUSED", nil
	}
	if resp.Rcode == dns.RcodeServerFailure {
		return "SERVFAIL", nil
	}
	if resp.Rcode == dns.RcodeNameError {
		return "NXDOMAIN", nil
	}
	if resp.Rcode != dns.RcodeSuccess {
		return "ERROR", fmt.Errorf("o nameserver retornou o rcode DNS %s", dns.RcodeToString[resp.Rcode])
	}
	if !resp.Authoritative {
		return "LAME", nil
	}
	expectedOwner := normalizeDNSName(domain)
	for _, answer := range resp.Answer {
		soa, ok := answer.(*dns.SOA)
		if ok && normalizeDNSName(soa.Hdr.Name) == expectedOwner {
			return "HEALTHY", nil
		}
	}

	return "LAME", nil
}

func (r *Resolver) ResolveAAAA(ctx context.Context, fqdn string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeAAAA)
	m.RecursionDesired = true
	resp, err := r.exchange(ctx, m)
	if err != nil {
		return nil, err
	}
	var ips []string
	if resp.Rcode == dns.RcodeSuccess {
		for _, ans := range resp.Answer {
			if a, ok := ans.(*dns.AAAA); ok {
				ips = append(ips, a.AAAA.String())
			}
		}
	}
	return ips, nil
}

func (r *Resolver) ResolveTXT(ctx context.Context, fqdn string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeTXT)
	m.RecursionDesired = true
	resp, err := r.exchange(ctx, m)
	if err != nil {
		return nil, err
	}
	var txts []string
	if resp.Rcode == dns.RcodeSuccess {
		for _, ans := range resp.Answer {
			if txt, ok := ans.(*dns.TXT); ok {
				txts = append(txts, strings.Join(txt.Txt, " "))
			}
		}
	}
	return txts, nil
}

func (r *Resolver) ResolveSRV(ctx context.Context, fqdn string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeSRV)
	m.RecursionDesired = true
	resp, err := r.exchange(ctx, m)
	if err != nil {
		return nil, err
	}
	var srvs []string
	if resp.Rcode == dns.RcodeSuccess {
		for _, ans := range resp.Answer {
			if srv, ok := ans.(*dns.SRV); ok {
				target := strings.TrimSuffix(strings.ToLower(srv.Target), ".")
				srvs = append(srvs, fmt.Sprintf("%s:%d", target, srv.Port))
			}
		}
	}
	return srvs, nil
}

func (r *Resolver) ResolveSOA(ctx context.Context, fqdn string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeSOA)
	m.RecursionDesired = true
	resp, err := r.exchange(ctx, m)
	if err != nil {
		return nil, err
	}
	var soas []string
	if resp != nil && resp.Rcode == dns.RcodeSuccess {
		for _, ans := range resp.Answer {
			if soa, ok := ans.(*dns.SOA); ok {
				soas = append(soas, fmt.Sprintf("%s %s", soa.Ns, soa.Mbox))
			}
		}
	}
	return soas, nil
}

func (r *Resolver) ResolveCAA(ctx context.Context, fqdn string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeCAA)
	m.RecursionDesired = true
	resp, err := r.exchange(ctx, m)
	if err != nil {
		return nil, err
	}
	var caas []string
	if resp != nil && resp.Rcode == dns.RcodeSuccess {
		for _, ans := range resp.Answer {
			if caa, ok := ans.(*dns.CAA); ok {
				caas = append(caas, fmt.Sprintf("%s %s", caa.Tag, caa.Value))
			}
		}
	}
	return caas, nil
}

func (r *Resolver) ResolvePTR(ctx context.Context, fqdn string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypePTR)
	m.RecursionDesired = true
	resp, err := r.exchange(ctx, m)
	if err != nil {
		return nil, err
	}
	var ptrs []string
	if resp != nil && resp.Rcode == dns.RcodeSuccess {
		for _, ans := range resp.Answer {
			if ptr, ok := ans.(*dns.PTR); ok {
				ptrs = append(ptrs, ptr.Ptr)
			}
		}
	}
	return ptrs, nil
}

// DiscoverProfile coleta concorrentemente todo o perfil DNS de um host.
// Essa é a única saída do motor de descoberta para o restante do fluxo de processamento.
func (r *Resolver) DiscoverProfile(ctx context.Context, host string) (core.DNSRecordSet, error) {
	var profile core.DNSRecordSet

	var wg sync.WaitGroup
	var mu sync.Mutex // Protege as escritas no perfil.
	successfulQueries := 0
	var firstQueryErr error

	// Executa cada tipo de consulta em paralelo.
	run := func(task func() ([]string, error), assign func([]string)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := task()
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstQueryErr == nil {
					firstQueryErr = err
				}
				return
			}
			successfulQueries++
			if len(res) > 0 {
				assign(res)
			}
		}()
	}

	run(func() ([]string, error) { return r.ResolveA(ctx, host) }, func(res []string) { profile.A = res })
	run(func() ([]string, error) { return r.ResolveAAAA(ctx, host) }, func(res []string) { profile.AAAA = res })
	run(func() ([]string, error) { return r.ResolveCNAMEChain(ctx, host) }, func(res []string) { profile.CNAME = res })
	run(func() ([]string, error) { return r.LookupNS(ctx, host) }, func(res []string) { profile.NS = res })
	run(func() ([]string, error) { return r.ResolveMX(ctx, host) }, func(res []string) { profile.MX = res })
	run(func() ([]string, error) { return r.ResolveTXT(ctx, host) }, func(res []string) { profile.TXT = res })
	if looksLikeSRVOwner(host) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			records, _, err := r.ResolveSRVRecords(ctx, host)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstQueryErr == nil {
					firstQueryErr = err
				}
				return
			}
			successfulQueries++
			if len(records) == 0 {
				return
			}
			legacy := make([]string, 0, len(records))
			for _, record := range records {
				legacy = append(legacy, fmt.Sprintf("%s:%d", record.Target, record.Port))
			}
			profile.SRVRecords = records
			profile.SRV = legacy
		}()
	}
	run(func() ([]string, error) { return r.ResolveSOA(ctx, host) }, func(res []string) { profile.SOA = res })
	run(func() ([]string, error) { return r.ResolveCAA(ctx, host) }, func(res []string) { profile.CAA = res })

	wg.Wait()
	if successfulQueries == 0 {
		if ctx.Err() != nil {
			return profile, ctx.Err()
		}
		if firstQueryErr != nil {
			return profile, fmt.Errorf("todas as consultas do perfil DNS falharam para %s: %w", host, firstQueryErr)
		}
		return profile, fmt.Errorf("todas as consultas do perfil DNS foram inconclusivas para %s", host)
	}
	if r.filterWildcard {
		isWildcard, signature, wildcardErr := r.IsWildcard(ctx, host)
		if wildcardErr == nil && isWildcard && profileMatchesWildcard(profile, signature) {
			return profile, fmt.Errorf("%w: %s", ErrWildcardFiltered, host)
		}
	}

	return profile, nil
}

func profileMatchesWildcard(profile core.DNSRecordSet, signature WildcardSignature) bool {
	if signature.Empty() {
		return false
	}
	return equalRRSet(profile.A, signature.A) &&
		equalRRSet(profile.AAAA, signature.AAAA) &&
		equalRRSet(profile.CNAME, signature.CNAME)
}

func looksLikeSRVOwner(host string) bool {
	labels := strings.Split(normalizeDNSName(host), ".")
	return len(labels) >= 3 && strings.HasPrefix(labels[0], "_") &&
		(labels[1] == "_tcp" || labels[1] == "_udp")
}

// AttemptAXFR tenta realizar uma transferência de zona (AXFR) via TCP contra o nameserver fornecido.
// Retorna true se a transferência foi bem-sucedida.
func (r *Resolver) AttemptAXFR(ctx context.Context, domain, nsServer string) (bool, error) {
	key := normalizeDNSName(domain) + "|" + normalizeDNSName(nsServer)
	if cached, ok := r.axfrCache.Load(key); ok {
		result := cached.(axfrResult)
		return result.success, result.err
	}
	value, err, _ := r.axfrGroup.Do(key, func() (interface{}, error) {
		if cached, ok := r.axfrCache.Load(key); ok {
			return cached.(axfrResult), nil
		}
		success, transferErr := r.attemptAXFRUncached(ctx, domain, nsServer)
		result := axfrResult{success: success, err: transferErr}
		if !errors.Is(transferErr, context.Canceled) && !errors.Is(transferErr, context.DeadlineExceeded) {
			r.axfrCache.Store(key, result)
		}
		return result, nil
	})
	if err != nil {
		return false, err
	}
	result := value.(axfrResult)
	return result.success, result.err
}

type axfrResult struct {
	success bool
	err     error
}

func (r *Resolver) attemptAXFRUncached(ctx context.Context, domain, nsServer string) (bool, error) {
	endpoint, endpointErr := r.nameserverEndpoint(ctx, nsServer)
	if endpointErr != nil {
		return false, endpointErr
	}

	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(domain))

	transfer := new(dns.Transfer)
	transfer.DialTimeout = r.operationTimeout()
	transfer.ReadTimeout = r.operationTimeout()

	if err := r.wait(ctx); err != nil {
		return false, err
	}
	env, err := transfer.In(m, endpoint)
	if err != nil {
		return false, err
	}

	success := false
	for e := range env {
		if e.Error != nil {
			continue // Erro em um envelope, mas pode já ter recebido algo ou falhado geral
		}
		if len(e.RR) > 0 {
			success = true // Registros recebidos
		}
	}

	return success, nil
}

func (r *Resolver) nameserverEndpoint(ctx context.Context, nameserver string) (string, error) {
	nameserver = strings.TrimSuffix(strings.TrimSpace(nameserver), ".")
	if nameserver == "" {
		return "", fmt.Errorf("nameserver vazio")
	}
	if _, _, err := net.SplitHostPort(nameserver); err == nil {
		endpoint, normalizeErr := normalizeResolverEndpoint(nameserver)
		if normalizeErr != nil {
			return "", fmt.Errorf("endpoint do nameserver inválido: %w", normalizeErr)
		}
		return endpoint, nil
	}
	if strings.HasPrefix(nameserver, "[") && strings.HasSuffix(nameserver, "]") {
		endpoint, normalizeErr := normalizeResolverEndpoint(nameserver)
		if normalizeErr != nil {
			return "", fmt.Errorf("endpoint do nameserver inválido: %w", normalizeErr)
		}
		return endpoint, nil
	}
	if ip := net.ParseIP(nameserver); ip != nil {
		return net.JoinHostPort(ip.String(), "53"), nil
	}
	if strings.Contains(nameserver, ":") {
		return "", fmt.Errorf("endpoint do nameserver inválido: %q", nameserver)
	}
	addresses, _ := r.ResolveA(ctx, nameserver)
	if len(addresses) == 0 {
		addresses, _ = r.ResolveAAAA(ctx, nameserver)
	}
	if len(addresses) == 0 {
		return "", fmt.Errorf("o nameserver %s não possui endereço", nameserver)
	}
	return net.JoinHostPort(addresses[0], "53"), nil
}

// CheckDNSSEC verifica o status do DNSSEC no domínio fornecido.
// Retorna um mapa contendo os detalhes detectados (presença de chaves e assinaturas).
func (r *Resolver) CheckDNSSEC(ctx context.Context, domain string) (map[string]bool, error) {
	key := normalizeDNSName(domain)
	if cached, ok := r.dnssecCache.Load(key); ok {
		return cloneBoolMap(cached.(map[string]bool)), nil
	}
	value, err, _ := r.dnssecGroup.Do(key, func() (interface{}, error) {
		if cached, ok := r.dnssecCache.Load(key); ok {
			return cloneBoolMap(cached.(map[string]bool)), nil
		}
		results, checkErr := r.checkDNSSECUncached(ctx, domain)
		if checkErr != nil {
			return nil, checkErr
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		r.dnssecCache.Store(key, cloneBoolMap(results))
		return results, nil
	})
	if err != nil {
		return nil, err
	}
	return cloneBoolMap(value.(map[string]bool)), nil
}

func (r *Resolver) checkDNSSECUncached(ctx context.Context, domain string) (map[string]bool, error) {
	fqdn := dns.Fqdn(domain)
	results := map[string]bool{
		"DNSKEY": false,
		"DS":     false,
		"RRSIG":  false,
	}

	// Consulta DNSKEY.
	mKey := new(dns.Msg)
	mKey.SetQuestion(fqdn, dns.TypeDNSKEY)
	mKey.RecursionDesired = true
	respKey, err := r.exchange(ctx, mKey)
	if err == nil && respKey.Rcode == dns.RcodeSuccess {
		for _, ans := range respKey.Answer {
			if _, ok := ans.(*dns.DNSKEY); ok {
				results["DNSKEY"] = true
				break
			}
		}
	}

	// Consulta DS.
	mDS := new(dns.Msg)
	mDS.SetQuestion(fqdn, dns.TypeDS)
	mDS.RecursionDesired = true
	respDS, err := r.exchange(ctx, mDS)
	if err == nil && respDS.Rcode == dns.RcodeSuccess {
		for _, ans := range respDS.Answer {
			if _, ok := ans.(*dns.DS); ok {
				results["DS"] = true
				break
			}
		}
	}

	// Consulta RRSIG por meio de um registro A com o bit DO ativado.
	mSig := new(dns.Msg)
	mSig.SetQuestion(fqdn, dns.TypeA)
	mSig.SetEdns0(4096, true) // Ativa o bit DNSSEC OK (DO).
	mSig.RecursionDesired = true
	respSig, err := r.exchange(ctx, mSig)
	if err == nil && respSig.Rcode == dns.RcodeSuccess {
		for _, ans := range respSig.Answer {
			if _, ok := ans.(*dns.RRSIG); ok {
				results["RRSIG"] = true
				break
			}
		}
	}

	return results, nil
}

func cloneBoolMap(values map[string]bool) map[string]bool {
	clone := make(map[string]bool, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}
