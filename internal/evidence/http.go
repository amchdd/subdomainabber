package evidence

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/pkg/ratelimit"
	"github.com/amchdd/subdomainabber/pkg/signatures"
)

const maxBodySize = 1 << 20 // Limite de 1 MB.

var userAgents = []struct {
	UA       string
	Platform string
	Version  string
}{
	{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36", "\"Windows\"", "125"},
	{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36", "\"macOS\"", "124"},
	{"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36", "\"Linux\"", "125"},
	{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0", "\"Windows\"", "125"},
}

var loadCDNSignatures = signatures.LoadCDNSignatures

func (c *HTTPCollector) SetRequestLimiter(limiter ratelimit.Waiter) {
	timeout := c.httpClient.Timeout
	c.httpClient.Timeout = 0
	c.httpClient.Transport = ratelimit.NewTimedTransport(limiter, c.httpClient.Transport, timeout)
}

// HTTPCollector faz requisições HTTP e HTTPS buscando evidências baseadas em assinaturas de corpo/status.
type HTTPCollector struct {
	httpClient       *http.Client
	sigs             []signatures.Fingerprint
	cdnSigs          []signatures.CDNSignature
	fetchHeaders     bool
	userAgent        string
	secChUAPlatform  string
	secChUA          string
	configurationErr error
}

func NewHTTPCollector(sigs []signatures.Fingerprint, timeout time.Duration, proxyURL string, followRedirects bool, userAgent string, fetchHeaders bool) *HTTPCollector {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // Para lidar com TLS expirado em CNAME quebrado
		},
		DisableKeepAlives:   false,
		MaxIdleConnsPerHost: 100,
		MaxIdleConns:        100,
		ForceAttemptHTTP2:   true,
	}

	var configurationErr error
	if proxyURL != "" {
		proxyList, proxyErr := parseHTTPProxyList(proxyURL)
		if proxyErr != nil {
			configurationErr = fmt.Errorf("configurando proxy HTTP: %w", proxyErr)
			// Mesmo que um chamador deixe de executar Validate, o transporte não
			// poderá transformar uma configuração inválida em conexão direta.
			transport.Proxy = func(*http.Request) (*url.URL, error) {
				return nil, configurationErr
			}
		} else {
			var proxyIndex uint64
			transport.Proxy = func(*http.Request) (*url.URL, error) {
				idx := atomic.AddUint64(&proxyIndex, 1) - 1
				return proxyList[idx%uint64(len(proxyList))], nil
			}
		}
	}

	if timeout == 0 {
		timeout = 5 * time.Second
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	if !followRedirects {
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse // Não seguir redirecionamentos
		}
	} else {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("interrompido após 10 redirecionamentos")
			}
			if len(via) == 0 || !sameRedirectHost(req.URL, via[0].URL) {
				return http.ErrUseLastResponse
			}
			return nil
		}
	}

	var finalUA string
	var secChUAPlatform string
	var secChUA string

	if userAgent != "" {
		finalUA = userAgent
	} else {
		uaProfile := userAgents[rand.Intn(len(userAgents))]
		finalUA = uaProfile.UA
		secChUAPlatform = uaProfile.Platform
		if strings.Contains(finalUA, "Edg") {
			secChUA = fmt.Sprintf(`"Microsoft Edge";v="%s", "Chromium";v="%s", "Not.A/Brand";v="24"`, uaProfile.Version, uaProfile.Version)
		} else if strings.Contains(finalUA, "Chrome") {
			secChUA = fmt.Sprintf(`"Google Chrome";v="%s", "Chromium";v="%s", "Not.A/Brand";v="24"`, uaProfile.Version, uaProfile.Version)
		}
	}

	cdnSigs, cdnErr := loadCDNSignatures()
	if cdnErr != nil {
		configurationErr = errors.Join(configurationErr, fmt.Errorf("carregando assinaturas CDN: %w", cdnErr))
	}

	return &HTTPCollector{
		httpClient:       client,
		sigs:             sigs,
		cdnSigs:          cdnSigs,
		fetchHeaders:     fetchHeaders,
		userAgent:        finalUA,
		secChUAPlatform:  secChUAPlatform,
		secChUA:          secChUA,
		configurationErr: configurationErr,
	}
}

func parseHTTPProxyList(raw string) ([]*url.URL, error) {
	content := raw
	if data, err := os.ReadFile(raw); err == nil {
		content = string(data)
	}
	parts := strings.FieldsFunc(content, func(character rune) bool {
		return character == ',' || character == '\n' || character == '\r'
	})
	if len(parts) == 0 {
		return nil, fmt.Errorf("a configuração de proxy está vazia")
	}
	result := make([]*url.URL, 0, len(parts))
	for index, part := range parts {
		parsed, err := url.Parse(strings.TrimSpace(part))
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https" && parsed.Scheme != "socks5" && parsed.Scheme != "socks5h") {
			return nil, fmt.Errorf("proxy inválido na posição %d", index+1)
		}
		result = append(result, parsed)
	}
	return result, nil
}

func (c *HTTPCollector) Validate() error {
	if c == nil {
		return fmt.Errorf("coletor HTTP ausente")
	}
	return c.configurationErr
}

func (c *HTTPCollector) Phase() CollectorPhase {
	return PhaseHTTPBaseline
}

// SetTransport permite injetar um RoundTripper personalizado (ex.: um dublê para testes).
func (c *HTTPCollector) SetTransport(rt http.RoundTripper) {
	if c.httpClient != nil {
		c.httpClient.Transport = rt
	}
}

func (c *HTTPCollector) Collect(ctx context.Context, analysis *core.HostAnalysis) error {
	if err := c.Validate(); err != nil {
		return err
	}
	analysis.AddTestedVector("HTTP")

	if !c.ShouldProbeHTTP(analysis) {
		return nil
	}

	for _, proto := range []string{"http", "https"} {
		targetURL := fmt.Sprintf("%s://%s", proto, analysis.Host)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err != nil {
			analysis.SetHTTPObservation(proto, newHTTPObservation(proto, 0, make(http.Header), nil, false, 0, "", err.Error()))
			continue
		}
		req.Header.Set("User-Agent", c.userAgent)
		req.Header.Set("Accept", "*/*")
		if c.secChUAPlatform != "" {
			req.Header.Set("Sec-CH-UA-Platform", c.secChUAPlatform)
			req.Header.Set("Sec-CH-UA-Mobile", "?0")
		}
		if c.secChUA != "" {
			req.Header.Set("Sec-CH-UA", c.secChUA)
		}

		start := time.Now()
		resp, err := c.httpClient.Do(req)
		duration := time.Since(start)
		if err != nil {
			analysis.SetHTTPObservation(proto, newHTTPObservation(proto, 0, make(http.Header), nil, false, duration, err.Error(), ""))
			continue
		}

		bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBodySize+1))
		closeErr := resp.Body.Close()
		parseError := ""
		complete := readErr == nil && closeErr == nil
		if len(bodyBytes) > maxBodySize {
			bodyBytes = bodyBytes[:maxBodySize]
			complete = false
			parseError = "o corpo da resposta excedeu o tamanho máximo"
		} else if readErr != nil {
			parseError = readErr.Error()
		} else if closeErr != nil {
			parseError = closeErr.Error()
		}
		observation := newHTTPObservation(proto, resp.StatusCode, resp.Header, bodyBytes, complete, duration, "", parseError)
		analysis.SetHTTPObservation(proto, observation)

		bodyStr := string(bodyBytes)
		statusCode := resp.StatusCode

		analysis.Server = resp.Header.Get("Server")
		analysis.ContentLength = resp.ContentLength
		if analysis.ContentLength <= 0 {
			analysis.ContentLength = int64(len(bodyBytes))
		}
		analysis.ResponseTimeMs = duration.Milliseconds()

		if c.fetchHeaders {
			if analysis.Headers == nil {
				analysis.Headers = make(map[string][]string)
			}
			for k, v := range resp.Header {
				analysis.Headers[k] = v
			}
		}

		// Detecção de CDN e Tecnologias
		for _, cdnSig := range c.cdnSigs {
			for headerKey, headerVal := range cdnSig.Headers {
				if val := resp.Header.Get(headerKey); val != "" {
					if headerVal == "" || strings.Contains(strings.ToLower(val), strings.ToLower(headerVal)) {
						analysis.CDN = cdnSig.Name
						analysis.Technologies = append(analysis.Technologies, cdnSig.Name)
						analysis.AddEvidence(core.Evidence{
							Type:        "CDN_DETECTED",
							Source:      proto,
							Description: fmt.Sprintf("CDN %s detectada pelo cabeçalho %s", cdnSig.Name, headerKey),
							Weight:      50,
							IsNegative:  true,
						})
						break
					}
				}
			}
		}

		// Adiciona as evidências HTTP
		analysis.AddEvidence(core.Evidence{
			Type:        "HTTP_RESPONSE",
			Source:      proto,
			Description: fmt.Sprintf("Recebido status %d no protocolo %s", statusCode, proto),
			Weight:      0,
			Metadata: map[string]string{
				"status":    fmt.Sprintf("%d", statusCode),
				"title":     observation.Title,
				"body_hash": observation.BodyHash,
			},
		})

		// 404 é um clássico indicador
		if statusCode == 404 {
			analysis.AddEvidence(core.Evidence{
				Type:        "HTTP_STATUS_404",
				Source:      proto,
				Description: "O código de status 404 pode indicar um recurso ausente no provedor",
				Weight:      10, // Alterado de 1 para 10.
			})
		}

		if statusCode == 401 || statusCode == 403 {
			analysis.AddEvidence(core.Evidence{
				Type:        "HTTP_AUTH_REQUIRED",
				Source:      proto,
				Description: fmt.Sprintf("Status %d indica recurso protegido, possivelmente ativo", statusCode),
				Weight:      30,
				IsNegative:  true,
			})
		}

		matchedAnyFingerprint := false
		// Respostas truncadas ou com erro de leitura permanecem disponíveis como
		// observação, mas nunca alimentam uma assinatura de takeover.
		if complete {
			// Verifica assinaturas baseadas no corpo ou nos cabeçalhos.
			for _, sig := range c.sigs {
				if sig.Fingerprint == "" {
					continue // Evita correspondência em NXDomain sem assinaturas HTTP
				}
				matchedCNAME, providerMatches := matchingCNAME(analysis.DNS.CNAME, sig.CNames)
				if !providerMatches {
					continue
				}

				// Avalia a assinatura com suporte a expressão regular e sem diferenciar maiúsculas de minúsculas.
				if signatures.MatchesFingerprint(bodyStr, &sig) {
					matchedAnyFingerprint = true
					candidate := core.ProviderCandidate{ProviderID: providerID(sig.Service), Service: sig.Service, CNAME: matchedCNAME, Vector: "CNAME", Resource: matchedCNAME}
					rule, eligible := eligibleTakeoverFingerprint(&sig, candidate, core.RawHTTPObservation{StatusCode: statusCode, Headers: resp.Header.Clone(), Body: bodyBytes, Complete: complete})
					evidenceType, description, weight, confidence := "HTTP_BODY_MATCH", "Assinatura HTTP específica do provedor identificado", 50, 80
					if !eligible {
						evidenceType, description, weight, confidence = "HTTP_FINGERPRINT_REVIEW", "Assinatura HTTP genérica ou inelegível exige revisão manual", 0, 40
					}
					analysis.AddEvidence(core.Evidence{
						Type:        evidenceType,
						Source:      sig.Service,
						Description: description,
						Weight:      weight,
						Confidence:  confidence,
						Metadata: map[string]string{
							"rule_id":             rule.RuleID,
							"matched_fingerprint": sig.Fingerprint,
							"matched_cname":       matchedCNAME,
							"provider_id":         providerID(sig.Service),
							"claimability":        rule.Claimability,
						},
					})
				}
			}
		}

		if complete && statusCode == 200 && !matchedAnyFingerprint {
			analysis.AddEvidence(core.Evidence{
				Type:        "HTTP_OK_ACTIVE",
				Source:      proto,
				Description: "Resposta HTTP 200 sem assinatura conhecida de recurso ausente",
				Weight:      0,
			})
		}
	}

	return nil
}

func sameRedirectHost(next, initial *url.URL) bool {
	if next == nil || initial == nil {
		return false
	}
	normalize := func(host string) string {
		return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	}
	return normalize(next.Hostname()) == normalize(initial.Hostname())
}

// ShouldProbeHTTP determina se vale a pena fazer a requisição HTTP.
// Evita onerar a rede em hosts que não possuem A ou CNAME válidos.
func (c *HTTPCollector) ShouldProbeHTTP(analysis *core.HostAnalysis) bool {
	// Se tem A ou CNAME, vale a pena bater no HTTP para varrer assinaturas
	if len(analysis.DNS.A) > 0 || len(analysis.DNS.AAAA) > 0 || len(analysis.DNS.CNAME) > 0 {
		return true
	}

	// Analisa se já existe alguma evidência de correspondência de CNAME que force a varredura
	for _, ev := range analysis.Evidences {
		if ev.Type == "CNAME_MATCH" {
			return true
		}
	}

	return false
}

func extractTitle(body string) string {
	start := strings.Index(strings.ToLower(body), "<title>")
	if start == -1 {
		return ""
	}
	start += 7 // len("<title>")
	end := strings.Index(strings.ToLower(body[start:]), "</title>")
	if end == -1 {
		return ""
	}

	title := strings.TrimSpace(body[start : start+end])
	// Limpar quebras de linha e tabulações que poluem o banco de dados
	title = strings.ReplaceAll(title, "\n", " ")
	title = strings.ReplaceAll(title, "\r", "")
	title = strings.ReplaceAll(title, "\t", " ")

	// Limitar tamanho
	if len(title) > 200 {
		return title[:197] + "..."
	}
	return title
}
