package evidence

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
)

func TestHTTPMutationPayloadsAreDistinctAndCalculated(t *testing.T) {
	ctx := testMutationContext("example.com:8080")
	tests := []struct {
		name  string
		probe HTTPMutation
		check func(*testing.T, []byte)
	}{
		{name: "null byte", probe: NullByteHostProbe{}, check: func(t *testing.T, payload []byte) {
			if !strings.Contains(string(payload), "example.com:8080\x00") {
				t.Fatalf("payload does not contain a real NUL byte: %q", payload)
			}
		}},
		{name: "whitespace", probe: HostWhitespaceProbe{}, check: func(t *testing.T, payload []byte) {
			if !strings.Contains(string(payload), "Host:  example.com:8080\r\n") {
				t.Fatalf("unexpected whitespace payload: %q", payload)
			}
		}},
		{name: "trailing dot", probe: HostTrailingDotProbe{}, check: func(t *testing.T, payload []byte) {
			if !strings.Contains(string(payload), "Host: example.com.:8080\r\n") {
				t.Fatalf("unexpected trailing-dot payload: %q", payload)
			}
		}},
		{name: "explicit port", probe: ExplicitPortProbe{}, check: func(t *testing.T, payload []byte) {
			if !strings.Contains(string(payload), "Host: example.com:8080\r\n") {
				t.Fatalf("unexpected explicit-port payload: %q", payload)
			}
		}},
		{name: "absolute form", probe: AbsoluteFormProbe{}, check: func(t *testing.T, payload []byte) {
			if !strings.HasPrefix(string(payload), "GET http://example.com:8080/ HTTP/1.1\r\n") {
				t.Fatalf("unexpected absolute-form payload: %q", payload)
			}
		}},
		{name: "CL.TE", probe: CLTEProbe{}, check: func(t *testing.T, payload []byte) {
			headers, body := splitRawRequest(t, payload)
			contentLength := requestContentLength(t, headers)
			if contentLength != len(body) {
				t.Fatalf("CL.TE Content-Length = %d, body length = %d", contentLength, len(body))
			}
			if !strings.HasPrefix(string(body), "0\r\n\r\n") {
				t.Fatalf("CL.TE body is not valid zero-chunk framing: %q", body)
			}
		}},
		{name: "TE.CL", probe: TECLProbe{}, check: func(t *testing.T, payload []byte) {
			headers, body := splitRawRequest(t, payload)
			contentLength := requestContentLength(t, headers)
			prefix := []byte("1\r\nZ")
			if contentLength != len(prefix) {
				t.Fatalf("TE.CL Content-Length = %d, calculated prefix = %d", contentLength, len(prefix))
			}
			if string(body) != "1\r\nZ\r\n0\r\n\r\n" {
				t.Fatalf("TE.CL body has invalid chunk delimiters: %q", body)
			}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := tt.probe.BuildMutation(ctx)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			tt.check(t, payload)
		})
	}
}

func TestFramingControlAndMutationBytesExactly(t *testing.T) {
	ctx := testMutationContext("example.com")
	tests := []struct {
		name                      string
		probe                     HTTPMutation
		wantControl, wantMutation string
	}{
		{name: "CL.TE", probe: CLTEProbe{},
			wantControl:  "POST / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: SubdomainAbber-Mutator/experimental\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: 1\r\n\r\nX",
			wantMutation: "POST / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: SubdomainAbber-Mutator/experimental\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX"},
		{name: "TE.CL", probe: TECLProbe{},
			wantControl:  "POST / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: SubdomainAbber-Mutator/experimental\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: 1\r\n\r\nZ",
			wantMutation: "POST / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: SubdomainAbber-Mutator/experimental\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nZ\r\n0\r\n\r\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			control, err := tt.probe.BuildControl(ctx)
			if err != nil {
				t.Fatal(err)
			}
			mutation, err := tt.probe.BuildMutation(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if string(control) != tt.wantControl {
				t.Fatalf("control bytes:\ngot  %q\nwant %q", control, tt.wantControl)
			}
			if string(mutation) != tt.wantMutation {
				t.Fatalf("mutation bytes:\ngot  %q\nwant %q", mutation, tt.wantMutation)
			}
		})
	}
}

func testMutationContext(host string) core.MutationContext {
	baseline := newHTTPObservation("http", 403, http.Header{"Server": []string{"cloudflare"}}, []byte("Access denied"), true, 0, "", "")
	mutationContext, err := mutationContextForAuthority(host, "http")
	if err != nil {
		panic(err)
	}
	mutationContext.Baseline = baseline
	mutationContext.ProviderCandidates = []core.ProviderCandidate{{
		ProviderID: "aws_s3",
		Service:    "AWS/S3",
		CNAME:      "bucket.s3.amazonaws.com",
	}}
	mutationContext.BlockDecision = decideBlock("http", baseline)
	return mutationContext
}

func splitRawRequest(t *testing.T, payload []byte) (string, []byte) {
	t.Helper()
	parts := strings.SplitN(string(payload), "\r\n\r\n", 2)
	if len(parts) != 2 {
		t.Fatalf("request has no header/body delimiter: %q", payload)
	}
	return parts[0], []byte(parts[1])
}

func requestContentLength(t *testing.T, headers string) int {
	t.Helper()
	for _, line := range strings.Split(headers, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "content-length:") {
			value, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(strings.ToLower(line), "content-length:")))
			if err != nil {
				t.Fatalf("invalid Content-Length: %v", err)
			}
			return value
		}
	}
	t.Fatalf("Content-Length not found in %q", headers)
	return 0
}
