package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
	"golang.org/x/net/html"
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
	if headers == nil {
		headers = make(http.Header)
	}
	normalized := normalizeHTTPBody(body)
	contentType := mediaType(headers.Get("Content-Type"))
	htmlDocument, passwordForm := inspectHTML(contentType, body)
	return core.HTTPObservation{
		Scheme:         scheme,
		StatusCode:     statusCode,
		Headers:        stableHTTPHeaders(headers),
		RawHeaders:     headers.Clone(),
		Body:           append([]byte(nil), body...),
		NormalizedBody: normalized,
		BodyHash:       hashBytes(normalized),
		BodyLength:     len(body),
		ContentType:    contentType,
		Location:       strings.TrimSpace(headers.Get("Location")),
		Title:          extractTitle(string(body)),
		Server:         headers.Get("Server"),
		ResponseKind:   responseKind(statusCode, headers, body),
		EdgeProvider:   edgeProvider(headers, body),
		HTMLDocument:   htmlDocument,
		PasswordForm:   passwordForm,
		Cookies:        observedCookies(headers),
		Complete:       complete,
		Duration:       duration,
		TransportError: transportError,
		ParseError:     parseError,
	}
}

func mediaType(value string) string {
	parsed, _, err := mime.ParseMediaType(value)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(strings.Split(value, ";")[0]))
	}
	return strings.ToLower(parsed)
}

func inspectHTML(contentType string, body []byte) (bool, bool) {
	if contentType != "text/html" && contentType != "application/xhtml+xml" {
		return false, false
	}
	lowerBody := strings.ToLower(string(body))
	markup := false
	for _, marker := range []string{"<!doctype", "<html", "<body", "<main", "<form"} {
		if strings.Contains(lowerBody, marker) {
			markup = true
			break
		}
	}
	if !markup {
		return false, false
	}
	document, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return false, false
	}
	hasDocument := false
	passwordForm := false
	var walk func(*html.Node, bool)
	walk = func(node *html.Node, insideForm bool) {
		if node.Type == html.ElementNode {
			switch strings.ToLower(node.Data) {
			case "html", "body", "main":
				hasDocument = true
			case "form":
				insideForm = true
			case "input":
				if insideForm {
					for _, attribute := range node.Attr {
						if strings.EqualFold(attribute.Key, "type") && strings.EqualFold(attribute.Val, "password") {
							passwordForm = true
						}
					}
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child, insideForm)
		}
	}
	walk(document, false)
	return hasDocument, passwordForm
}

func observedCookies(headers http.Header) []core.HTTPCookie {
	response := &http.Response{Header: headers}
	var result []core.HTTPCookie
	for _, cookie := range response.Cookies() {
		result = append(result, core.HTTPCookie{
			Name: cookie.Name, Domain: cookie.Domain, Path: cookie.Path,
			Secure: cookie.Secure, HTTPOnly: cookie.HttpOnly,
			SameSite: sameSite(cookie.SameSite), Sensitive: sensitiveCookie(cookie.Name),
		})
	}
	return result
}

func sameSite(value http.SameSite) string {
	switch value {
	case http.SameSiteStrictMode:
		return "STRICT"
	case http.SameSiteLaxMode:
		return "LAX"
	case http.SameSiteNoneMode:
		return "NONE"
	default:
		return ""
	}
}

func sensitiveCookie(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, edge := range []string{"__cf_bm", "cf_clearance", "ak_bmsc", "bm_sz", "awsalb", "awsalbcors"} {
		if name == edge {
			return false
		}
	}
	for _, marker := range []string{"session", "sess", "auth", "token", "jwt", "phpsessid", "jsessionid"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return name == "sid"
}

func responseKind(status int, headers http.Header, body []byte) string {
	if edgeProvider(headers, body) != "" {
		return "EDGE_RESPONSE"
	}
	switch {
	case status == http.StatusNotFound || status == http.StatusGone:
		return "RESOURCE_NOT_AVAILABLE"
	case status >= 200 && status < 300:
		return "APPLICATION_RESPONSE"
	case status >= 300 && status < 400:
		return "REDIRECT_RESPONSE"
	case status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusTooManyRequests:
		return "ACCESS_RESPONSE"
	case status >= 500:
		return "ERROR_RESPONSE"
	default:
		return "OTHER_RESPONSE"
	}
}

func edgeProvider(headers http.Header, body []byte) string {
	text := strings.ToLower(headers.Get("Server") + " " + string(body))
	cases := []struct {
		name    string
		headers []string
		markers []string
	}{
		{name: "CLOUDFLARE", headers: []string{"Cf-Ray"}, markers: []string{"cloudflare"}},
		{name: "CLOUDFRONT", headers: []string{"X-Amz-Cf-Id", "X-Amz-Cf-Pop"}, markers: []string{"cloudfront"}},
		{name: "FASTLY", headers: []string{"X-Served-By", "Fastly-Debug-Digest"}, markers: []string{"fastly"}},
		{name: "AKAMAI", headers: []string{"X-Akamai-Transformed", "Akamai-Grn"}, markers: []string{"akamai"}},
		{name: "VERCEL", headers: []string{"X-Vercel-Id"}, markers: []string{"vercel"}},
		{name: "NETLIFY", headers: []string{"X-Nf-Request-Id"}, markers: []string{"netlify"}},
		{name: "AZURE_FRONT_DOOR", headers: []string{"X-Azure-Ref"}, markers: []string{"azure front door"}},
		{name: "GOOGLE_FRONTEND", headers: []string{"X-Gfe-Request-Trace"}, markers: []string{"google frontend", "gws", "gfe"}},
	}
	for _, candidate := range cases {
		for _, name := range candidate.headers {
			if headers.Get(name) != "" {
				return candidate.name
			}
		}
		for _, marker := range candidate.markers {
			if strings.Contains(text, marker) {
				return candidate.name
			}
		}
	}
	return ""
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
