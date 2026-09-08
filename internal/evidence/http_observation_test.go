package evidence

import (
	"net/http"
	"testing"
)

func TestHTTPObservationNormalizesVolatileData(t *testing.T) {
	first := newHTTPObservation("http", 403, http.Header{
		"Date":         []string{"Tue, 21 Jul 2026 12:00:00 GMT"},
		"X-Request-Id": []string{"aaaaaaaa"},
		"Server":       []string{"edge"},
	}, []byte(`request-id: abcdefgh12345678 timestamp 2026-07-21T12:00:00Z`), true, 0, "", "")
	second := newHTTPObservation("http", 403, http.Header{
		"Date":         []string{"Tue, 21 Jul 2026 12:01:00 GMT"},
		"X-Request-Id": []string{"bbbbbbbb"},
		"Server":       []string{"edge"},
	}, []byte(`request-id: zyxwvuts87654321 timestamp 2026-07-21T12:01:00Z`), true, 0, "", "")

	if first.BodyHash != second.BodyHash {
		t.Fatalf("volatile bodies produced different hashes: %s != %s", first.BodyHash, second.BodyHash)
	}
	if _, exists := first.Headers["Date"]; exists {
		t.Fatal("volatile Date header was retained")
	}
	if _, exists := first.Headers["X-Request-Id"]; exists {
		t.Fatal("volatile request ID header was retained")
	}
}

func TestHTTPObservationRecognizesApplicationSignals(t *testing.T) {
	headers := http.Header{
		"Content-Type": {"text/html; charset=utf-8"},
		"Set-Cookie": {
			"session_id=secret; Path=/; HttpOnly",
			"__cf_bm=edge; Path=/; Secure; HttpOnly",
		},
	}
	observation := newHTTPObservation("http", http.StatusOK, headers,
		[]byte("<!doctype html><html><body><form><input type=password></form></body></html>"), true, 0, "", "")
	if !observation.HTMLDocument || !observation.PasswordForm || observation.ResponseKind != "APPLICATION_RESPONSE" {
		t.Fatalf("sinais de aplicação não reconhecidos: %+v", observation)
	}
	if len(observation.Cookies) != 2 || !observation.Cookies[0].Sensitive || observation.Cookies[1].Sensitive {
		t.Fatalf("cookies classificados incorretamente: %+v", observation.Cookies)
	}
	if len(observation.RawHeaders["Set-Cookie"]) != 2 {
		t.Fatalf("headers brutos não preservados: %+v", observation.RawHeaders)
	}
}

func TestHTTPObservationRecognizesEdge(t *testing.T) {
	observation := newHTTPObservation("https", http.StatusForbidden,
		http.Header{"Server": {"cloudflare"}, "Cf-Ray": {"abc"}}, []byte("Access denied"), true, 0, "", "")
	if observation.ResponseKind != "EDGE_RESPONSE" || observation.EdgeProvider != "CLOUDFLARE" {
		t.Fatalf("resposta de borda não reconhecida: %+v", observation)
	}
}

func TestBlockDecisionRequiresStatusOrChallengeNotServerAlone(t *testing.T) {
	serverOnly := newHTTPObservation("http", 200, http.Header{"Server": []string{"cloudflare"}}, []byte("normal page"), true, 0, "", "")
	if decision := decideBlock("http", serverOnly); decision.Blocked {
		t.Fatalf("server header alone marked baseline blocked: %#v", decision)
	}
	blocked := newHTTPObservation("http", 403, http.Header{"Server": []string{"cloudflare"}}, []byte("Access denied"), true, 0, "", "")
	if decision := decideBlock("http", blocked); !decision.Blocked || decision.Confidence < 60 {
		t.Fatalf("explicit blocked response was not recognized: %#v", decision)
	}
}
