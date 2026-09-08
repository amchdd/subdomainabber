package inference_test

import (
	"net/http"
	"testing"

	"github.com/amchdd/subdomainabber/internal/classification"
	"github.com/amchdd/subdomainabber/internal/core"
)

func TestRedirect404IsNotDangling(t *testing.T) {
	analysis := &core.HostAnalysis{Host: "crashreport.example.test"}
	analysis.SetHTTPObservation("http", core.HTTPObservation{
		Scheme: "http", StatusCode: http.StatusMovedPermanently, Location: "https://crashreport.example.test/", Complete: true,
	})
	analysis.SetHTTPObservation("https", core.HTTPObservation{
		Scheme: "https", StatusCode: http.StatusNotFound, ResponseKind: "RESOURCE_NOT_AVAILABLE", Complete: true,
	})
	analysis.SetRedirectChain("http", core.RedirectChain{
		Scheme: "http", FinalURL: "https://crashreport.example.test/", StoppedReason: "FINAL_RESPONSE",
		Hops: []core.RedirectHop{
			{Index: 0, URL: "http://crashreport.example.test/", Hostname: "crashreport.example.test", Scheme: "http", StatusCode: 301, Location: "https://crashreport.example.test/", DNSStatus: core.DNSStatusResolved},
			{Index: 1, URL: "https://crashreport.example.test/", Hostname: "crashreport.example.test", Scheme: "https", StatusCode: 404, DNSStatus: core.DNSStatusResolved},
		},
	})

	classification.Process(analysis)
	if hasEvidence(analysis, "DANGLING_REDIRECT") {
		t.Fatalf("HTTP 404 no destino virou dangling: %+v", analysis.Evidences)
	}
	if !hasEvidence(analysis, "HTTP_HTTPS_UPGRADE_PRESENT") {
		t.Fatalf("upgrade não reconhecido: %+v", analysis.Evidences)
	}
}

func TestFailedUpgradeIsNotHealthy(t *testing.T) {
	analysis := &core.HostAnalysis{Host: "app.example.test"}
	analysis.SetHTTPObservation("http", core.HTTPObservation{Scheme: "http", StatusCode: 301, Location: "https://missing.example.test/", Complete: true})
	analysis.SetRedirectChain("http", core.RedirectChain{
		Scheme: "http", FinalURL: "https://missing.example.test/", StoppedReason: "DESTINATION_NXDOMAIN",
		Hops: []core.RedirectHop{{Hostname: "missing.example.test", Scheme: "https", DNSStatus: core.DNSStatusNXDomain}},
	})
	classification.Process(analysis)
	if hasEvidence(analysis, "HTTP_HTTPS_UPGRADE_PRESENT") {
		t.Fatal("destino HTTPS sem DNS foi tratado como upgrade concluído")
	}
	if !hasEvidence(analysis, "DANGLING_REDIRECT") {
		t.Fatal("o destino quebrado deixou de ser reportado")
	}
}

func TestBlockedEdgeIsSuppressed(t *testing.T) {
	body := []byte("access denied")
	analysis := &core.HostAnalysis{Host: "sso.example.test"}
	analysis.SetHTTPObservation("http", core.HTTPObservation{
		Scheme: "http", StatusCode: 403, Server: "cloudflare", ResponseKind: "EDGE_RESPONSE",
		EdgeProvider:   "CLOUDFLARE",
		NormalizedBody: body, BodyHash: "same", BodyLength: len(body), Complete: true,
	})
	analysis.SetHTTPObservation("https", core.HTTPObservation{
		Scheme: "https", StatusCode: 403, Server: "cloudflare", ResponseKind: "EDGE_RESPONSE",
		EdgeProvider:   "CLOUDFLARE",
		NormalizedBody: body, BodyHash: "same", BodyLength: len(body), Complete: true,
	})

	classification.Process(analysis)
	if analysis.ResultState != core.ResultSuppressed || analysis.Classification == classification.LevelMisconfigured {
		t.Fatalf("bloqueio de borda não foi suprimido: classe=%s decisão=%+v", analysis.Classification, analysis.Decision)
	}
	if analysis.Decision == nil || analysis.Decision.Rule != "EDGE_BLOCKED_NO_EXPOSURE" || analysis.Decision.ImpactConfidence != 0 {
		t.Fatalf("decisão inesperada: %+v", analysis.Decision)
	}
	if analysis.HTTPCorrelation == nil || analysis.HTTPCorrelation.HTTPEdgeProvider != "CLOUDFLARE" || !hasReason(analysis.Decision.ReasonCodes, "EDGE_PROVIDER_CLOUDFLARE") {
		t.Fatalf("provedor de borda ausente da correlação: %+v", analysis.HTTPCorrelation)
	}
}

func TestPlaintextLoginIsConfirmed(t *testing.T) {
	body := []byte("<html><body><form><input type=password></form></body></html>")
	analysis := &core.HostAnalysis{Host: "login.example.test"}
	analysis.SetHTTPObservation("http", core.HTTPObservation{
		Scheme: "http", StatusCode: 200, ContentType: "text/html", ResponseKind: "APPLICATION_RESPONSE",
		NormalizedBody: body, BodyHash: "same", BodyLength: len(body), HTMLDocument: true, PasswordForm: true, Complete: true,
	})
	analysis.SetHTTPObservation("https", core.HTTPObservation{
		Scheme: "https", StatusCode: 200, ContentType: "text/html", ResponseKind: "APPLICATION_RESPONSE",
		NormalizedBody: body, BodyHash: "same", BodyLength: len(body), HTMLDocument: true, PasswordForm: true, Complete: true,
	})

	classification.Process(analysis)
	if analysis.ResultState != core.ResultConfirmed || analysis.Classification != classification.LevelExposed {
		t.Fatalf("interface sem TLS não foi confirmada: classe=%s decisão=%+v", analysis.Classification, analysis.Decision)
	}
	if !hasEvidence(analysis, "PLAINTEXT_AUTH_INTERFACE") || analysis.HTTPCorrelation == nil || analysis.HTTPCorrelation.BodySimilarity != 100 {
		t.Fatalf("correlação incompleta: evidências=%+v correlação=%+v", analysis.Evidences, analysis.HTTPCorrelation)
	}
	if analysis.HTTPCorrelation.TransportPriority != 11 {
		t.Fatalf("prioridade de transporte = %d, esperado 11", analysis.HTTPCorrelation.TransportPriority)
	}
}

func TestHeadersIgnoreNonHTMLCSP(t *testing.T) {
	analysis := &core.HostAnalysis{Host: "api.example.test", TestedVectors: []string{"SEC_HEADERS"}}
	analysis.SetHTTPObservation("https", core.HTTPObservation{
		Scheme: "https", StatusCode: 200, ContentType: "application/json", Complete: true,
	})

	classification.Process(analysis)
	if hasEvidence(analysis, "HTTPS_CSP_ABSENT") {
		t.Fatalf("CSP foi avaliada em JSON: %+v", analysis.Evidences)
	}
	if analysis.ResultState != core.ResultObservation {
		t.Fatalf("postura HSTS não ficou como observação: %+v", analysis.Decision)
	}
}

func TestSensitiveApplicationCookieOverHTTP(t *testing.T) {
	analysis := &core.HostAnalysis{Host: "app.example.test"}
	analysis.SetHTTPObservation("http", core.HTTPObservation{
		Scheme: "http", StatusCode: 200, ContentType: "text/html", HTMLDocument: true, Complete: true,
		Cookies: []core.HTTPCookie{{Name: "session_id", Sensitive: true}},
	})

	classification.Process(analysis)
	if analysis.ResultState != core.ResultConfirmed || !hasEvidence(analysis, "HTTP_SENSITIVE_COOKIE_WITHOUT_SECURE") {
		t.Fatalf("cookie sensível não foi confirmado: decisão=%+v evidências=%+v", analysis.Decision, analysis.Evidences)
	}
}

func hasEvidence(analysis *core.HostAnalysis, evidenceType string) bool {
	for _, evidence := range analysis.Evidences {
		if evidence.Type == evidenceType {
			return true
		}
	}
	return false
}

func hasReason(reasons []string, expected string) bool {
	for _, reason := range reasons {
		if reason == expected {
			return true
		}
	}
	return false
}
