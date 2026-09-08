package inference

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/amchdd/subdomainabber/internal/core"
)

func Analyze(analysis *core.HostAnalysis) {
	if analysis == nil {
		return
	}
	analysis.Inferences = nil
	analysis.Decision = nil
	analysis.ResultState = ""
	analysis.HTTPCorrelation = nil
	removeDerivedEvidence(analysis)
	analyzeHTTP(analysis)
	analyzeRedirects(analysis)
	analyzeHeaders(analysis)
}

func analyzeHTTP(analysis *core.HostAnalysis) {
	httpObservation, hasHTTP := analysis.HTTPObservation("http")
	httpsObservation, hasHTTPS := analysis.HTTPObservation("https")
	if !hasHTTP && !hasHTTPS {
		return
	}

	correlation := correlate(httpObservation, hasHTTP, httpsObservation, hasHTTPS)
	analysis.SetHTTPCorrelation(correlation)
	if hasHTTP && hasHTTPS && httpObservation.Complete && httpsObservation.Complete && correlation.BodySimilarity >= 90 {
		addEvidence(analysis, core.Evidence{
			Type: "HTTP_HTTPS_CONTENT_CORRELATED", Source: "INFERENCE",
			Description: "As respostas HTTP e HTTPS apresentam conteúdo equivalente.",
			Weight:      0, Confidence: 95,
			Metadata: map[string]string{"similarity": formatPercent(correlation.BodySimilarity)},
		})
	}

	if hasHTTPS && httpsObservation.Complete && isRedirectStatus(httpsObservation.StatusCode) {
		if downgradeURL, downgraded := httpsDowngrade(analysis, httpsObservation); downgraded {
			addEvidence(analysis, core.Evidence{
				Type: "HTTPS_DOWNGRADE_REDIRECT", Source: "INFERENCE",
				Description: "O endpoint HTTPS redireciona para uma URL HTTP.",
				Weight:      15, Confidence: 100,
				Metadata: map[string]string{"location": downgradeURL},
			})
			addInference(analysis, "HTTPS_DOWNGRADE", core.ResultCandidate, "HTTPS_DOWNGRADE_REDIRECT", []string{"HTTPS_REDIRECTS_TO_HTTP"}, 100, 95, 70)
		}
	}

	if !hasHTTP || !httpObservation.Complete {
		return
	}
	upgradeURL, upgraded := httpsUpgrade(analysis, httpObservation)
	if upgraded {
		addEvidence(analysis, core.Evidence{
			Type: "HTTP_HTTPS_UPGRADE_PRESENT", Source: "INFERENCE",
			Description: "A cadeia HTTP conclui o upgrade para HTTPS.",
			Weight:      0, Confidence: 100,
			Metadata: map[string]string{"location": upgradeURL},
		})
		if inconsistentHTTPSPort(upgradeURL) {
			addEvidence(analysis, core.Evidence{
				Type: "HTTP_HTTPS_PORT_INCONSISTENT", Source: "INFERENCE",
				Description: "O redirecionamento de upgrade usa uma porta HTTPS não convencional.",
				Weight:      10, Confidence: 100,
				Metadata: map[string]string{"location": upgradeURL},
			})
			addInference(analysis, "HTTP_UPGRADE_NONSTANDARD_PORT", core.ResultCandidate, "HTTP_HTTPS_PORT_INCONSISTENT", []string{"HTTP_REDIRECTS_TO_NONSTANDARD_HTTPS_PORT"}, 100, 85, 35)
		} else {
			addInference(analysis, "HTTP_HTTPS_UPGRADE", core.ResultHealthy, "", []string{"HTTP_REDIRECTS_TO_HTTPS"}, 100, 100, 0)
		}
		return
	}

	addEvidence(analysis, core.Evidence{
		Type: "HTTP_NO_HTTPS_UPGRADE", Source: "INFERENCE",
		Description: "O endpoint HTTP não conclui o upgrade para HTTPS.",
		Weight:      0, Confidence: 100,
		Metadata: map[string]string{"status": strconv.Itoa(httpObservation.StatusCode), "location": httpObservation.Location},
	})

	if !hasHTTPS || !httpsObservation.Complete {
		addEvidence(analysis, core.Evidence{
			Type: "HTTPS_UNAVAILABLE", Source: "INFERENCE",
			Description: "O endpoint HTTP respondeu, mas a coleta HTTPS não foi concluída.",
			Weight:      0, Confidence: 80,
		})
	}

	reasons := []string{"HTTP_NO_HTTPS_UPGRADE", "HTTP_STATUS_" + strconv.Itoa(httpObservation.StatusCode)}
	edge := httpObservation.ResponseKind == "EDGE_RESPONSE" || httpsObservation.ResponseKind == "EDGE_RESPONSE"
	if edge {
		reasons = append(reasons, "EDGE_RESPONSE")
	}
	for _, provider := range []string{httpObservation.EdgeProvider, httpsObservation.EdgeProvider} {
		if provider != "" && !contains(reasons, "EDGE_PROVIDER_"+provider) {
			reasons = append(reasons, "EDGE_PROVIDER_"+provider)
		}
	}
	if hasHTTPS && httpsObservation.Complete {
		reasons = append(reasons, "HTTPS_STATUS_"+strconv.Itoa(httpsObservation.StatusCode))
	}

	switch {
	case blockedStatus(httpObservation.StatusCode):
		finding := "HTTP_BLOCKED_WITHOUT_REDIRECT"
		addEvidence(analysis, core.Evidence{
			Type: finding, Source: "INFERENCE",
			Description: "O endpoint HTTP não redireciona, mas a resposta bloqueia o acesso ao conteúdo.",
			Weight:      0, Confidence: 100,
		})
		if edge {
			finding = ""
			addEvidence(analysis, core.Evidence{
				Type: "HTTP_EDGE_BLOCK", Source: "INFERENCE",
				Description: "A ausência de upgrade ocorreu em uma resposta de bloqueio da borda.",
				Weight:      0, Confidence: 95,
			})
		}
		rule := "HTTP_BLOCKED_NO_EXPOSURE"
		if edge {
			rule = "EDGE_BLOCKED_NO_EXPOSURE"
		}
		addInference(analysis, rule, core.ResultSuppressed, finding, reasons, 100, 95, 0)
	case unavailableStatus(httpObservation.StatusCode):
		addEvidence(analysis, core.Evidence{
			Type: "RESOURCE_NOT_AVAILABLE", Source: "INFERENCE",
			Description: "O endpoint HTTP não disponibiliza o recurso solicitado.",
			Weight:      0, Confidence: 100,
		})
		addInference(analysis, "HTTP_RESOURCE_NOT_AVAILABLE", core.ResultSuppressed, "", reasons, 100, 95, 0)
	case httpObservation.StatusCode >= 500:
		addEvidence(analysis, core.Evidence{
			Type: "HTTP_ERROR_WITHOUT_REDIRECT", Source: "INFERENCE",
			Description: "A resposta HTTP terminou em erro sem demonstrar exposição da aplicação.",
			Weight:      0, Confidence: 100,
		})
		addInference(analysis, "HTTP_ERROR_NO_EXPOSURE", core.ResultSuppressed, "", reasons, 100, 90, 0)
	case httpObservation.StatusCode >= 200 && httpObservation.StatusCode < 300:
		analyzePlaintext(analysis, httpObservation, correlation, reasons)
	default:
		addInference(analysis, "HTTP_NO_UPGRADE_OBSERVED", core.ResultObservation, "", reasons, 100, 80, 0)
	}
}

func analyzePlaintext(analysis *core.HostAnalysis, observation core.HTTPObservation, correlation core.HTTPCorrelation, reasons []string) {
	var sensitive []string
	for _, cookie := range observation.Cookies {
		if cookie.Sensitive && !cookie.Secure {
			sensitive = append(sensitive, cookie.Name)
		}
	}
	if observation.HTMLDocument {
		reasons = append(reasons, "HTML_CONTENT")
		if correlation.BodySimilarity >= 90 {
			reasons = append(reasons, "HTTP_HTTPS_CONTENT_SIMILAR")
		}
		addEvidence(analysis, core.Evidence{
			Type: "PLAINTEXT_WEB_CONTENT", Source: "INFERENCE",
			Description: "Conteúdo HTML navegável está disponível por HTTP sem upgrade para HTTPS.",
			Weight:      20, Confidence: 95,
			Metadata: map[string]string{"similarity": formatPercent(correlation.BodySimilarity)},
		})
	}
	if observation.PasswordForm {
		reasons = append(reasons, "PASSWORD_FORM")
		addEvidence(analysis, core.Evidence{
			Type: "PLAINTEXT_AUTH_INTERFACE", Source: "INFERENCE",
			Description: "Um formulário com campo de senha está disponível por HTTP.",
			Weight:      60, Confidence: 100,
		})
	}
	if len(sensitive) > 0 {
		reasons = append(reasons, "SENSITIVE_COOKIE_WITHOUT_SECURE")
		addEvidence(analysis, core.Evidence{
			Type: "HTTP_SENSITIVE_COOKIE_WITHOUT_SECURE", Source: "INFERENCE",
			Description: "A resposta HTTP emite cookie de aplicação sensível sem o atributo Secure.",
			Weight:      60, Confidence: 95,
			Metadata: map[string]string{"cookies": strings.Join(sensitive, ",")},
		})
	}
	priority := 2
	signals := []string{"HTTP_SERVED"}
	if correlation.BodySimilarity >= 90 {
		priority += 3
		signals = append(signals, "SAME_CONTENT")
	}
	if observation.HTMLDocument {
		priority++
		signals = append(signals, "HTML")
	}
	if observation.PasswordForm {
		priority += 4
		signals = append(signals, "LOGIN_FORM")
	}
	if len(sensitive) > 0 {
		priority += 4
		signals = append(signals, "SENSITIVE_COOKIE")
	}
	if httpsObservation, ok := analysis.HTTPObservation("https"); ok && httpsObservation.Complete && header(httpsObservation.Headers, "Strict-Transport-Security") == "" {
		priority++
		signals = append(signals, "HSTS_ABSENT")
	}
	if analysis.HTTPCorrelation != nil {
		analysis.HTTPCorrelation.TransportPriority = priority
		analysis.HTTPCorrelation.TransportSignals = append([]string(nil), signals...)
	}
	addEvidence(analysis, core.Evidence{
		Type: "TRANSPORT_PRIORITY_SCORE", Source: "INFERENCE",
		Description: "A prioridade de validação do transporte foi calculada sem alterar a severidade.",
		Weight:      0, Confidence: 100,
		Metadata: map[string]string{"score": strconv.Itoa(priority), "signals": strings.Join(signals, ",")},
	})

	switch {
	case observation.PasswordForm:
		addInference(analysis, "PLAINTEXT_AUTH_INTERFACE", core.ResultConfirmed, "PLAINTEXT_AUTH_INTERFACE", reasons, 100, 100, 90)
	case len(sensitive) > 0:
		addInference(analysis, "SENSITIVE_COOKIE_OVER_HTTP", core.ResultConfirmed, "HTTP_SENSITIVE_COOKIE_WITHOUT_SECURE", reasons, 100, 95, 85)
	case observation.HTMLDocument:
		addInference(analysis, "PLAINTEXT_WEB_CONTENT", core.ResultCandidate, "PLAINTEXT_WEB_CONTENT", reasons, 100, 95, 45)
	default:
		addInference(analysis, "HTTP_NO_UPGRADE_OBSERVED", core.ResultObservation, "", reasons, 100, 80, 0)
	}
}

func analyzeRedirects(analysis *core.HostAnalysis) {
	for _, chain := range analysis.Redirects {
		if len(chain.Hops) == 0 {
			continue
		}
		last := chain.Hops[len(chain.Hops)-1]
		switch chain.StoppedReason {
		case "DESTINATION_NXDOMAIN", "DESTINATION_NO_DATA":
			addEvidence(analysis, core.Evidence{
				Type: "DANGLING_REDIRECT", Source: "INFERENCE",
				Description: "O cabeçalho Location aponta para um hostname sem resolução DNS utilizável.",
				Weight:      20, Confidence: 95,
				Metadata: map[string]string{
					"target_host": last.Hostname, "target_url": last.URL,
					"dns_status": string(last.DNSStatus), "cname": strings.Join(last.CNAME, ","),
				},
			})
			addInference(analysis, "REDIRECT_DESTINATION_DNS_MISSING", core.ResultCandidate, "DANGLING_REDIRECT", []string{"REDIRECT_LOCATION_PRESENT", "DESTINATION_" + string(last.DNSStatus)}, 100, 95, 35)
		case "DESTINATION_SERVFAIL", "DESTINATION_TIMEOUT", "DESTINATION_REFUSED", "DESTINATION_ERROR":
			addInference(analysis, "REDIRECT_DESTINATION_INCONCLUSIVE", core.ResultInconclusive, "", []string{"REDIRECT_LOCATION_PRESENT", chain.StoppedReason}, 100, 70, 0)
		case "DESTINATION_PROVIDER_ERROR":
			addEvidence(analysis, core.Evidence{
				Type: "DANGLING_REDIRECT", Source: "INFERENCE",
				Description: "O destino do redirect apresentou uma assinatura específica de recurso ausente no provedor.",
				Weight:      20, Confidence: 95,
				Metadata: map[string]string{
					"target_host": last.Hostname, "target_url": last.URL, "provider": last.Provider,
					"matched_fingerprint": last.MatchedFingerprint, "http_status": strconv.Itoa(last.StatusCode),
				},
			})
			addInference(analysis, "REDIRECT_DESTINATION_PROVIDER_ERROR", core.ResultCandidate, "DANGLING_REDIRECT", []string{"REDIRECT_LOCATION_PRESENT", "PROVIDER_SPECIFIC_ERROR"}, 100, 95, 45)
		case "UNSUPPORTED_PROTOCOL":
			addInference(analysis, "UNSUPPORTED_PROTOCOL", core.ResultInconclusive, "", []string{"REDIRECT_LOCATION_PRESENT", "UNSUPPORTED_PROTOCOL"}, 100, 100, 0)
		}
	}
}

func analyzeHeaders(analysis *core.HostAnalysis) {
	if !contains(analysis.TestedVectors, "SEC_HEADERS") {
		return
	}
	observation, ok := analysis.HTTPObservation("https")
	if !ok || !observation.Complete {
		return
	}
	hsts := header(observation.Headers, "Strict-Transport-Security")
	if hsts == "" {
		addEvidence(analysis, core.Evidence{
			Type: "HTTPS_HSTS_ABSENT", Source: "INFERENCE",
			Description: "O cabeçalho Strict-Transport-Security não foi observado na resposta HTTPS.",
			Weight:      0, Confidence: 100,
		})
		addInference(analysis, "HSTS_POSTURE_ONLY", core.ResultObservation, "", []string{"HTTPS_RESPONSE", "HSTS_ABSENT"}, 100, 100, 0)
	} else {
		lower := strings.ToLower(hsts)
		addEvidence(analysis, core.Evidence{
			Type: "HTTPS_HSTS_PRESENT", Source: "INFERENCE",
			Description: "A resposta HTTPS publica uma política HSTS.",
			Weight:      0, Confidence: 100, IsNegative: true,
			Metadata: map[string]string{
				"value":              hsts,
				"max_age":            hstsMaxAge(hsts),
				"include_subdomains": strconv.FormatBool(strings.Contains(lower, "includesubdomains")),
				"preload":            strconv.FormatBool(strings.Contains(lower, "preload")),
			},
		})
	}

	if observation.StatusCode < 200 || observation.StatusCode >= 300 || !observation.HTMLDocument {
		return
	}
	csp := header(observation.Headers, "Content-Security-Policy")
	if csp == "" {
		addEvidence(analysis, core.Evidence{
			Type: "HTTPS_CSP_ABSENT", Source: "INFERENCE",
			Description: "A página HTML HTTPS não publica Content-Security-Policy; trata-se de uma observação de hardening.",
			Weight:      0, Confidence: 100,
		})
		addInference(analysis, "CSP_HARDENING_ONLY", core.ResultObservation, "", []string{"HTTPS_STATUS_2XX", "HTML_CONTENT", "CSP_ABSENT"}, 100, 100, 0)
	} else {
		addEvidence(analysis, core.Evidence{
			Type: "HTTPS_CSP_PRESENT", Source: "INFERENCE",
			Description: "A página HTML HTTPS publica Content-Security-Policy.",
			Weight:      0, Confidence: 100, IsNegative: true,
		})
	}
}

func hstsMaxAge(value string) string {
	for _, directive := range strings.Split(value, ";") {
		name, amount, ok := strings.Cut(strings.TrimSpace(directive), "=")
		if ok && strings.EqualFold(strings.TrimSpace(name), "max-age") {
			return strings.TrimSpace(amount)
		}
	}
	return ""
}

func correlate(httpObservation core.HTTPObservation, hasHTTP bool, httpsObservation core.HTTPObservation, hasHTTPS bool) core.HTTPCorrelation {
	result := core.HTTPCorrelation{}
	if hasHTTP {
		result.HTTPStatus = httpObservation.StatusCode
		result.HTTPContentType = httpObservation.ContentType
		result.HTTPBodyHash = httpObservation.BodyHash
		result.HTTPBodyLength = httpObservation.BodyLength
		result.HTTPServer = httpObservation.Server
		result.HTTPLocation = httpObservation.Location
		result.HTTPResponseKind = httpObservation.ResponseKind
		result.HTTPEdgeProvider = httpObservation.EdgeProvider
	}
	if hasHTTPS {
		result.HTTPSStatus = httpsObservation.StatusCode
		result.HTTPSContentType = httpsObservation.ContentType
		result.HTTPSBodyHash = httpsObservation.BodyHash
		result.HTTPSBodyLength = httpsObservation.BodyLength
		result.HTTPSServer = httpsObservation.Server
		result.HTTPSLocation = httpsObservation.Location
		result.HTTPSResponseKind = httpsObservation.ResponseKind
		result.HTTPSEdgeProvider = httpsObservation.EdgeProvider
	}
	if hasHTTP && hasHTTPS {
		result.SameServer = httpObservation.Server != "" && strings.EqualFold(httpObservation.Server, httpsObservation.Server)
		result.BodySimilarity = bodySimilarity(httpObservation.NormalizedBody, httpsObservation.NormalizedBody, httpObservation.BodyHash, httpsObservation.BodyHash)
		if httpObservation.StatusCode == httpsObservation.StatusCode {
			result.ReasonCodes = append(result.ReasonCodes, "SAME_STATUS")
		}
		if result.SameServer {
			result.ReasonCodes = append(result.ReasonCodes, "SAME_SERVER")
		}
		if result.BodySimilarity >= 90 {
			result.ReasonCodes = append(result.ReasonCodes, "SIMILAR_CONTENT")
		}
	}
	return result
}

func bodySimilarity(left, right []byte, leftHash, rightHash string) float64 {
	if len(left) == 0 && len(right) == 0 {
		return 0
	}
	if leftHash != "" && leftHash == rightHash {
		return 100
	}
	leftFields := strings.Fields(strings.ToLower(string(left)))
	rightFields := strings.Fields(strings.ToLower(string(right)))
	if len(leftFields) == 0 || len(rightFields) == 0 {
		return 0
	}
	counts := make(map[string]int, len(leftFields))
	for _, field := range leftFields {
		counts[field]++
	}
	overlap := 0
	for _, field := range rightFields {
		if counts[field] > 0 {
			overlap++
			counts[field]--
		}
	}
	return 200 * float64(overlap) / float64(len(leftFields)+len(rightFields))
}

func httpsUpgrade(analysis *core.HostAnalysis, observation core.HTTPObservation) (string, bool) {
	if chain, ok := analysis.Redirects["http"]; ok {
		complete := chain.StoppedReason == "FINAL_RESPONSE" || chain.StoppedReason == "DESTINATION_PROVIDER_ERROR"
		return chain.FinalURL, complete && strings.HasPrefix(strings.ToLower(chain.FinalURL), "https://")
	}
	if !isRedirectStatus(observation.StatusCode) {
		return observation.Location, false
	}
	target, err := url.Parse(observation.Location)
	return observation.Location, err == nil && strings.EqualFold(target.Scheme, "https") && target.Hostname() != ""
}

func httpsDowngrade(analysis *core.HostAnalysis, observation core.HTTPObservation) (string, bool) {
	if chain, ok := analysis.Redirects["https"]; ok && strings.HasPrefix(strings.ToLower(chain.FinalURL), "http://") {
		return chain.FinalURL, true
	}
	target, err := url.Parse(observation.Location)
	return observation.Location, err == nil && strings.EqualFold(target.Scheme, "http") && target.Hostname() != ""
}

func inconsistentHTTPSPort(location string) bool {
	target, err := url.Parse(location)
	return err == nil && target.Port() != "" && target.Port() != "443"
}

func isRedirectStatus(status int) bool {
	return status == http.StatusMovedPermanently || status == http.StatusFound || status == http.StatusSeeOther || status == http.StatusTemporaryRedirect || status == http.StatusPermanentRedirect
}

func blockedStatus(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusNotAcceptable || status == http.StatusTooManyRequests
}

func unavailableStatus(status int) bool {
	return status == http.StatusNotFound || status == http.StatusGone
}

func header(headers map[string][]string, name string) string {
	for key, values := range headers {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return strings.TrimSpace(values[0])
		}
	}
	return ""
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}

func addEvidence(analysis *core.HostAnalysis, evidence core.Evidence) {
	for _, existing := range analysis.Evidences {
		if existing.Type == evidence.Type && existing.Source == evidence.Source {
			return
		}
	}
	analysis.AddEvidence(evidence)
}

func addInference(analysis *core.HostAnalysis, rule string, state core.ResultState, finding string, reasons []string, observation, classification, impact int) {
	analysis.AddInference(core.Inference{
		Rule: rule, State: state, Finding: finding, ReasonCodes: append([]string(nil), reasons...),
		ObservationConfidence: observation, ClassificationConfidence: classification,
		ImpactConfidence: impact, ImpactConfirmed: state == core.ResultConfirmed,
	})
}

func removeDerivedEvidence(analysis *core.HostAnalysis) {
	filtered := analysis.Evidences[:0]
	for _, evidence := range analysis.Evidences {
		if evidence.Source != "INFERENCE" {
			filtered = append(filtered, evidence)
		}
	}
	analysis.Evidences = filtered
}

func formatPercent(value float64) string {
	return strconv.FormatFloat(value, 'f', 1, 64)
}
