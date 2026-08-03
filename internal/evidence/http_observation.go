package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
)

var dynamicBodyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b\d{4}-\d{2}-\d{2}[t ][0-9:.+-]+z?\b`),
	regexp.MustCompile(`(?i)\b(?:mon|tue|wed|thu|fri|sat|sun),\s+\d{1,2}\s+[a-z]{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+gmt\b`),
	regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b`),
	regexp.MustCompile(`(?i)(request[-_ ]?id|trace[-_ ]?id|nonce|challenge|token)(["'=:\s]+)[a-z0-9._~+/=-]{8,}`),
	regexp.MustCompile(`(?i)\b[0-9a-f]{24,}\b`),
}

var volatileHTTPHeaders = map[string]struct{}{
	"Date":             {},
	"Set-Cookie":       {},
	"X-Request-Id":     {},
	"X-Correlation-Id": {},
	"X-Amzn-Trace-Id":  {},
	"Traceparent":      {},
	"Cf-Ray":           {},
	"Server-Timing":    {},
}

func normalizeHTTPBody(body []byte) []byte {
	normalized := string(body)
	for _, pattern := range dynamicBodyPatterns {
		normalized = pattern.ReplaceAllString(normalized, "${1}${2}<dynamic>")
	}
	normalized = strings.Join(strings.Fields(normalized), " ")
	return []byte(normalized)
}

func stableHTTPHeaders(headers http.Header) map[string][]string {
	stable := make(map[string][]string)
	for name, values := range headers {
		canonical := http.CanonicalHeaderKey(name)
		if _, volatile := volatileHTTPHeaders[canonical]; volatile {
			continue
		}
		stable[canonical] = append([]string(nil), values...)
	}
	return stable
}

func hashBytes(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func newHTTPObservation(scheme string, statusCode int, headers http.Header, body []byte, complete bool, duration time.Duration, transportError, parseError string) core.HTTPObservation {
	normalized := normalizeHTTPBody(body)
	return core.HTTPObservation{
		Scheme:         scheme,
		StatusCode:     statusCode,
		Headers:        stableHTTPHeaders(headers),
		Body:           append([]byte(nil), body...),
		NormalizedBody: normalized,
		BodyHash:       hashBytes(normalized),
		Title:          extractTitle(string(body)),
		Server:         headers.Get("Server"),
		Complete:       complete,
		Duration:       duration,
		TransportError: transportError,
		ParseError:     parseError,
	}
}

func decideBlock(scheme string, observation core.HTTPObservation) core.BlockDecision {
	decision := core.BlockDecision{BaselineID: fmt.Sprintf("%s:%d:%s", scheme, observation.StatusCode, observation.BodyHash)}
	blockedStatus := observation.StatusCode == http.StatusUnauthorized || observation.StatusCode == http.StatusForbidden || observation.StatusCode == http.StatusNotAcceptable || observation.StatusCode == http.StatusTooManyRequests
	if blockedStatus {
		decision.Blocked = true
		decision.Confidence = 60
		decision.Reasons = append(decision.Reasons, fmt.Sprintf("status HTTP de bloqueio %d", observation.StatusCode))
	}

	normalizedBody := strings.ToLower(string(observation.NormalizedBody))
	serverAndBody := strings.ToLower(observation.Server) + " " + normalizedBody
	wafSignals := []string{
		"cloudflare", "incapsula", "akamai", "sucuri", "imperva",
		"access denied", "request blocked", "challenge",
		"enable javascript", "checking your browser", "verify you are human",
	}
	for _, signal := range wafSignals {
		if strings.Contains(serverAndBody, signal) {
			decision.Reasons = append(decision.Reasons, "sinal de WAF/challenge: "+signal)
			if blockedStatus {
				decision.Confidence = 85
			} else if strings.Contains(normalizedBody, signal) {
				decision.Blocked = true
				decision.Confidence = 70
			}
			break
		}
	}
	if !observation.Complete || observation.TransportError != "" || observation.ParseError != "" {
		decision.Blocked = false
		decision.Confidence = 0
		decision.Reasons = append(decision.Reasons, "linha de base incompleta ou com falha")
	}
	return decision
}
