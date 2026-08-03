package evidence

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
	netproxy "golang.org/x/net/proxy"
)

const (
	defaultRawBodyLimit = 1 << 20
	maxRawHeaderBytes   = 64 << 10
)

type HTTPRawTransport interface {
	Send(context.Context, core.MutationContext, []byte) core.RawHTTPObservation
}

type NetworkHTTPRawTransport struct {
	Timeout  time.Duration
	MaxBody  int
	Dialer   *net.Dialer
	ProxyURL *url.URL
	proxyErr error
}

func (transport *NetworkHTTPRawTransport) SetProxy(rawProxy string) error {
	if rawProxy == "" {
		transport.ProxyURL = nil
		transport.proxyErr = nil
		return nil
	}
	selected := ""
	if data, err := os.ReadFile(rawProxy); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if value := strings.TrimSpace(line); value != "" {
				selected = value
				break
			}
		}
	} else {
		for _, item := range strings.Split(rawProxy, ",") {
			if value := strings.TrimSpace(item); value != "" {
				selected = value
				break
			}
		}
	}
	if selected == "" {
		transport.ProxyURL = nil
		transport.proxyErr = fmt.Errorf("a configuração de proxy não contém endpoint utilizável")
		return transport.proxyErr
	}
	proxyURL, err := url.Parse(selected)
	if err != nil {
		transport.ProxyURL = nil
		transport.proxyErr = fmt.Errorf("proxy HTTP raw inválido")
		return transport.proxyErr
	}
	if proxyURL.Host == "" || (proxyURL.Scheme != "http" && proxyURL.Scheme != "https" && proxyURL.Scheme != "socks5" && proxyURL.Scheme != "socks5h") {
		transport.ProxyURL = nil
		transport.proxyErr = fmt.Errorf("o HTTP Mutator raw aceita um proxy http://, https:// ou socks5://")
		return transport.proxyErr
	}
	transport.ProxyURL = proxyURL
	transport.proxyErr = nil
	return nil
}

func NewNetworkHTTPRawTransport(timeout time.Duration) *NetworkHTTPRawTransport {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &NetworkHTTPRawTransport{
		Timeout: timeout,
		MaxBody: defaultRawBodyLimit,
		Dialer:  &net.Dialer{Timeout: timeout},
	}
}

func (transport *NetworkHTTPRawTransport) Send(ctx context.Context, mutationContext core.MutationContext, payload []byte) core.RawHTTPObservation {
	started := time.Now()
	observation := core.RawHTTPObservation{Headers: make(map[string][]string)}
	if transport.proxyErr != nil {
		observation.TransportError = transport.proxyErr.Error()
		observation.Duration = time.Since(started)
		return observation
	}
	host, port, err := mutationEndpoint(mutationContext)
	if err != nil {
		observation.TransportError = err.Error()
		observation.Duration = time.Since(started)
		return observation
	}

	address := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := transport.dial(ctx, address)
	if err != nil {
		setRawTransportError(&observation, err)
		observation.Duration = time.Since(started)
		return observation
	}
	defer conn.Close()

	if strings.EqualFold(mutationContext.Scheme, "https") {
		if mutationContext.TLSServerName == "" {
			observation.TransportError = "o nome de servidor TLS é obrigatório no transporte HTTPS raw"
			observation.Duration = time.Since(started)
			return observation
		}
		tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: mutationContext.TLSServerName}) //nolint:gosec
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			setRawTransportError(&observation, err)
			observation.Duration = time.Since(started)
			return observation
		}
		conn = tlsConn
	}

	deadline := time.Now().Add(transport.Timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		observation.TransportError = err.Error()
		observation.Duration = time.Since(started)
		return observation
	}
	if err := writeAll(conn, payload); err != nil {
		setRawTransportError(&observation, err)
		observation.Duration = time.Since(started)
		return observation
	}

	maxBody := transport.MaxBody
	if maxBody <= 0 {
		maxBody = defaultRawBodyLimit
	}
	observation = readRawHTTPObservation(bufio.NewReader(conn), maxBody)
	observation.Duration = time.Since(started)
	return observation
}

func (transport *NetworkHTTPRawTransport) dial(ctx context.Context, targetAddress string) (net.Conn, error) {
	if transport.ProxyURL == nil {
		return transport.Dialer.DialContext(ctx, "tcp", targetAddress)
	}
	if transport.ProxyURL.Scheme == "socks5" || transport.ProxyURL.Scheme == "socks5h" {
		dialer, err := netproxy.FromURL(transport.ProxyURL, transport.Dialer)
		if err != nil {
			return nil, err
		}
		if contextDialer, ok := dialer.(netproxy.ContextDialer); ok {
			return contextDialer.DialContext(ctx, "tcp", targetAddress)
		}
		return dialer.Dial("tcp", targetAddress)
	}
	proxyAddress := transport.ProxyURL.Host
	if _, _, err := net.SplitHostPort(proxyAddress); err != nil {
		if transport.ProxyURL.Scheme == "https" {
			proxyAddress = net.JoinHostPort(proxyAddress, "443")
		} else {
			proxyAddress = net.JoinHostPort(proxyAddress, "80")
		}
	}
	conn, err := transport.Dialer.DialContext(ctx, "tcp", proxyAddress)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(transport.Timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return nil, err
	}
	if transport.ProxyURL.Scheme == "https" {
		host := transport.ProxyURL.Hostname()
		tlsConn := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		conn = tlsConn
	}
	var request strings.Builder
	fmt.Fprintf(&request, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddress, targetAddress)
	if transport.ProxyURL.User != nil {
		password, _ := transport.ProxyURL.User.Password()
		token := base64.StdEncoding.EncodeToString([]byte(transport.ProxyURL.User.Username() + ":" + password))
		fmt.Fprintf(&request, "Proxy-Authorization: Basic %s\r\n", token)
	}
	request.WriteString("Proxy-Connection: keep-alive\r\n\r\n")
	if err := writeAll(conn, []byte(request.String())); err != nil {
		conn.Close()
		return nil, err
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT: %w", err)
	}
	if response.Body != nil {
		response.Body.Close()
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		conn.Close()
		return nil, fmt.Errorf("o proxy CONNECT retornou %s", response.Status)
	}
	return conn, nil
}

func mutationEndpoint(mutationContext core.MutationContext) (string, int, error) {
	host := mutationContext.DialHost
	port := mutationContext.DialPort
	if host == "" || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("endpoint de mutação inválido %q:%d", host, port)
	}
	return host, port, nil
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}

func readRawHTTPObservation(reader *bufio.Reader, maxBody int) core.RawHTTPObservation {
	observation := core.RawHTTPObservation{Headers: make(map[string][]string)}
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		setRawTransportError(&observation, err)
		return observation
	}
	statusLine = strings.TrimRight(statusLine, "\r\n")
	parts := strings.Fields(statusLine)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		observation.ParseError = "linha de status HTTP malformada"
		return observation
	}
	statusCode, err := strconv.Atoi(parts[1])
	if err != nil || statusCode < 100 || statusCode > 999 {
		observation.ParseError = "código de status HTTP inválido"
		return observation
	}
	observation.StatusCode = statusCode

	headerBytes := 0
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			setRawTransportError(&observation, readErr)
			return observation
		}
		headerBytes += len(line)
		if headerBytes > maxRawHeaderBytes {
			observation.ParseError = "os cabeçalhos HTTP excederam o tamanho máximo"
			return observation
		}
		if line == "\r\n" || line == "\n" {
			break
		}
		name, value, found := strings.Cut(strings.TrimRight(line, "\r\n"), ":")
		if !found || strings.TrimSpace(name) == "" {
			observation.ParseError = "cabeçalho HTTP malformado"
			return observation
		}
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
		observation.Headers[canonical] = append(observation.Headers[canonical], strings.TrimSpace(value))
	}

	if responseHasNoBody(statusCode) {
		observation.Complete = true
		return observation
	}
	if headerContainsToken(observation.Headers, "Transfer-Encoding", "chunked") {
		readChunkedBody(reader, maxBody, &observation)
		return observation
	}
	if contentLengthValue := firstHeader(observation.Headers, "Content-Length"); contentLengthValue != "" {
		contentLength, parseErr := strconv.ParseInt(contentLengthValue, 10, 64)
		if parseErr != nil || contentLength < 0 {
			observation.ParseError = "Content-Length inválido"
			return observation
		}
		if contentLength > int64(maxBody) {
			observation.ParseError = "o corpo HTTP excedeu o tamanho máximo"
			return observation
		}
		body := make([]byte, int(contentLength))
		read, readErr := io.ReadFull(reader, body)
		observation.Body = body[:read]
		if readErr != nil {
			setRawTransportError(&observation, readErr)
			return observation
		}
		observation.Complete = true
		return observation
	}

	body, readErr := io.ReadAll(io.LimitReader(reader, int64(maxBody)+1))
	if len(body) > maxBody {
		observation.Body = body[:maxBody]
		observation.ParseError = "o corpo HTTP excedeu o tamanho máximo"
		return observation
	}
	observation.Body = body
	if readErr != nil {
		setRawTransportError(&observation, readErr)
		return observation
	}
	observation.Complete = true
	return observation
}

func readChunkedBody(reader *bufio.Reader, maxBody int, observation *core.RawHTTPObservation) {
	var body []byte
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			setRawTransportError(observation, err)
			return
		}
		sizeText := strings.TrimSpace(strings.SplitN(line, ";", 2)[0])
		size, parseErr := strconv.ParseInt(sizeText, 16, 64)
		if parseErr != nil || size < 0 {
			observation.ParseError = "tamanho de chunk inválido"
			return
		}
		if size == 0 {
			for {
				trailer, trailerErr := reader.ReadString('\n')
				if trailerErr != nil {
					setRawTransportError(observation, trailerErr)
					return
				}
				if trailer == "\r\n" || trailer == "\n" {
					observation.Body = body
					observation.Complete = true
					return
				}
			}
		}
		if int64(len(body))+size > int64(maxBody) {
			observation.Body = body
			observation.ParseError = "o corpo HTTP excedeu o tamanho máximo"
			return
		}
		chunk := make([]byte, int(size)+2)
		if _, err := io.ReadFull(reader, chunk); err != nil {
			setRawTransportError(observation, err)
			return
		}
		if !strings.HasSuffix(string(chunk), "\r\n") {
			observation.ParseError = "chunk sem delimitador CRLF"
			return
		}
		body = append(body, chunk[:len(chunk)-2]...)
	}
}

func responseHasNoBody(statusCode int) bool {
	return statusCode >= 100 && statusCode < 200 || statusCode == http.StatusNoContent || statusCode == http.StatusNotModified
}

func firstHeader(headers map[string][]string, name string) string {
	values := headers[http.CanonicalHeaderKey(name)]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func headerContainsToken(headers map[string][]string, name, token string) bool {
	for _, value := range headers[http.CanonicalHeaderKey(name)] {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func setRawTransportError(observation *core.RawHTTPObservation, err error) {
	if err == nil {
		return
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		observation.ParseError = err.Error()
		return
	}
	var netError net.Error
	if errors.As(err, &netError) && netError.Timeout() {
		observation.TimedOut = true
		observation.TransportError = err.Error()
		return
	}
	errorText := strings.ToLower(err.Error())
	var errno syscall.Errno
	if strings.Contains(errorText, "reset") || strings.Contains(errorText, "forcibly closed") ||
		(errors.As(err, &errno) && (errno == syscall.ECONNRESET || errno == 10053 || errno == 10054)) {
		observation.ConnectionReset = true
	}
	observation.TransportError = err.Error()
}
