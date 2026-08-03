package evidence

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
)

type labParserMode string

const (
	labContentLength labParserMode = "content-length"
	labChunked       labParserMode = "chunked"
	labReject        labParserMode = "reject-ambiguous"
)

const (
	labFramingDifferential   = "FRAMING_DIFFERENTIAL"
	labNoFramingDifferential = "NO_FRAMING_DIFFERENTIAL"
	labFramingRejected       = "AMBIGUOUS_FRAMING_REJECTED"
)

type labTrace struct {
	FrontConsumed, BackendConsumed, BackendRemaining int
	Rejected                                         bool
}

func TestTwoHopFramingLabUsesRealTransportAndResponse(t *testing.T) {
	ctx := testMutationContext("example.com")
	clte, _ := (CLTEProbe{}).BuildMutation(ctx)
	tecl, _ := (TECLProbe{}).BuildMutation(ctx)
	clControl, _ := (CLTEProbe{}).BuildControl(ctx)
	teControl, _ := (TECLProbe{}).BuildControl(ctx)
	tests := []struct {
		name              string
		control, mutation []byte
		front, backend    labParserMode
		wantMutation      string
		wantRemaining     int
	}{
		{"CL.TE", clControl, clte, labContentLength, labChunked, labFramingDifferential, 1},
		{"TE.CL", teControl, tecl, labChunked, labContentLength, labFramingDifferential, 7},
		{"both CL", clControl, clte, labContentLength, labContentLength, labNoFramingDifferential, 0},
		{"both TE", teControl, tecl, labChunked, labChunked, labNoFramingDifferential, 0},
		{"front rejects", clControl, clte, labReject, labChunked, labFramingRejected, 0},
		{"backend rejects", teControl, tecl, labChunked, labReject, labFramingRejected, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			address, traces, closeLab := startRealTwoHopLab(t, tt.front, tt.backend)
			defer closeLab()
			host, portText, _ := net.SplitHostPort(address)
			port, _ := strconv.Atoi(portText)
			networkCtx := core.MutationContext{DialHost: host, DialPort: port, HTTPAuthority: address, Scheme: "http"}
			transport := NewNetworkHTTPRawTransport(time.Second)
			control := transport.Send(context.Background(), networkCtx, tt.control)
			mutation := transport.Send(context.Background(), networkCtx, tt.mutation)
			if control.StatusCode != 200 || string(control.Body) != labNoFramingDifferential {
				t.Fatalf("control observation = %#v", control)
			}
			if string(mutation.Body) != tt.wantMutation {
				t.Fatalf("mutation result = %q, want %q", mutation.Body, tt.wantMutation)
			}
			if strings.Contains(strings.ToLower(string(mutation.Body)), "bucket") {
				t.Fatalf("framing lab fabricated provider fingerprint: %q", mutation.Body)
			}
			controlTrace := <-traces
			if controlTrace.BackendRemaining != 0 {
				t.Fatalf("control trace = %#v", controlTrace)
			}
			if tt.front != labReject {
				mutationTrace := <-traces
				if mutationTrace.BackendRemaining != tt.wantRemaining {
					t.Fatalf("mutation trace = %#v, want remaining=%d", mutationTrace, tt.wantRemaining)
				}
			}
		})
	}
}

func startRealTwoHopLab(t *testing.T, frontMode, backendMode labParserMode) (string, <-chan labTrace, func()) {
	t.Helper()
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		backend.Close()
		t.Fatal(err)
	}
	done := make(chan struct{})
	traces := make(chan labTrace, 8)
	go labBackendLoop(backend, backendMode, traces, done)
	go labFrontLoop(front, backend.Addr().String(), frontMode, done)
	return front.Addr().String(), traces, func() { close(done); front.Close(); backend.Close() }
}

func labBackendLoop(listener net.Listener, mode labParserMode, traces chan<- labTrace, done <-chan struct{}) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			raw, _ := io.ReadAll(conn)
			consumed, parseErr := labConsumedBytes(raw, mode)
			status, body := 200, labNoFramingDifferential
			headerEnd := strings.Index(string(raw), "\r\n\r\n") + 4
			frontConsumed := 0
			if headerEnd > 3 {
				frontConsumed = len(raw) - headerEnd
			}
			trace := labTrace{FrontConsumed: frontConsumed, BackendConsumed: consumed}
			if parseErr != nil {
				status, body, trace.Rejected = 400, labFramingRejected, true
			} else {
				trace.BackendRemaining = frontConsumed - consumed
				if trace.BackendRemaining > 0 {
					status, body = 409, labFramingDifferential
				}
			}
			traces <- trace
			fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, httpStatusText(status), len(body), body)
		}(conn)
		select {
		case <-done:
			return
		default:
		}
	}
}

func labFrontLoop(listener net.Listener, backendAddress string, mode labParserMode, done <-chan struct{}) {
	for {
		client, err := listener.Accept()
		if err != nil {
			return
		}
		go func(client net.Conn) {
			defer client.Close()
			raw, readErr := labReadOne(bufio.NewReader(client), mode)
			if readErr != nil {
				body := labFramingRejected
				fmt.Fprintf(client, "HTTP/1.1 400 Bad Request\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
				return
			}
			backend, err := net.DialTimeout("tcp", backendAddress, time.Second)
			if err != nil {
				return
			}
			writeAll(backend, raw)
			if tcp, ok := backend.(*net.TCPConn); ok {
				tcp.CloseWrite()
			}
			io.Copy(client, backend)
			backend.Close()
		}(client)
		select {
		case <-done:
			return
		default:
		}
	}
}

func labReadOne(reader *bufio.Reader, mode labParserMode) ([]byte, error) {
	var raw strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		raw.WriteString(line)
		if line == "\r\n" {
			break
		}
	}
	headers := strings.TrimSuffix(raw.String(), "\r\n\r\n")
	hasCL := strings.Contains(strings.ToLower(headers), "content-length:")
	hasTE := strings.Contains(strings.ToLower(headers), "transfer-encoding: chunked")
	if mode == labReject && hasCL && hasTE {
		return nil, fmt.Errorf("ambiguous")
	}
	useTE := hasTE && (mode == labChunked || !hasCL)
	if useTE {
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return nil, err
			}
			raw.WriteString(line)
			size, err := strconv.ParseInt(strings.TrimSpace(line), 16, 64)
			if err != nil {
				return nil, err
			}
			if size == 0 {
				trailer, err := reader.ReadString('\n')
				if err != nil {
					return nil, err
				}
				raw.WriteString(trailer)
				break
			}
			chunk := make([]byte, int(size)+2)
			if _, err := io.ReadFull(reader, chunk); err != nil {
				return nil, err
			}
			raw.Write(chunk)
		}
	} else if hasCL {
		length := requestContentLengthFromHeaders(headers)
		if length < 0 {
			return nil, fmt.Errorf("invalid CL")
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(reader, body); err != nil {
			return nil, err
		}
		raw.Write(body)
	}
	return []byte(raw.String()), nil
}

func labConsumedBytes(request []byte, mode labParserMode) (int, error) {
	parts := strings.SplitN(string(request), "\r\n\r\n", 2)
	if len(parts) != 2 {
		return 0, fmt.Errorf("missing delimiter")
	}
	headers, body := parts[0], []byte(parts[1])
	lower := strings.ToLower(headers)
	hasCL, hasTE := strings.Contains(lower, "content-length:"), strings.Contains(lower, "transfer-encoding: chunked")
	if mode == labReject && hasCL && hasTE {
		return 0, fmt.Errorf("ambiguous")
	}
	if hasTE && (mode == labChunked || !hasCL) {
		return consumedChunkedBytes(body)
	}
	if hasCL {
		length := requestContentLengthFromHeaders(headers)
		if length < 0 || length > len(body) {
			return 0, fmt.Errorf("invalid CL")
		}
		return length, nil
	}
	return len(body), nil
}

func requestContentLengthFromHeaders(headers string) int {
	for _, line := range strings.Split(headers, "\r\n") {
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "Content-Length") {
			n, err := strconv.Atoi(strings.TrimSpace(value))
			if err == nil {
				return n
			}
		}
	}
	return -1
}
func consumedChunkedBytes(body []byte) (int, error) {
	offset := 0
	for {
		end := strings.Index(string(body[offset:]), "\r\n")
		if end < 0 {
			return 0, fmt.Errorf("chunk line")
		}
		size, err := strconv.ParseInt(string(body[offset:offset+end]), 16, 64)
		if err != nil {
			return 0, err
		}
		offset += end + 2
		if size == 0 {
			if len(body) < offset+2 || string(body[offset:offset+2]) != "\r\n" {
				return 0, fmt.Errorf("zero chunk")
			}
			return offset + 2, nil
		}
		if int64(len(body)-offset) < size+2 {
			return 0, fmt.Errorf("incomplete")
		}
		offset += int(size) + 2
	}
}
func httpStatusText(status int) string {
	if status == 404 {
		return "Not Found"
	}
	if status == 400 {
		return "Bad Request"
	}
	if status == 409 {
		return "Conflict"
	}
	return "Forbidden"
}
