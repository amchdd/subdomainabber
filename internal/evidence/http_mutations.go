package evidence

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/amchdd/subdomainabber/internal/core"
)

type HTTPMutation interface {
	Name() string
	Description() string
	Applicability(core.MutationContext) bool
	BuildControl(core.MutationContext) ([]byte, error)
	BuildMutation(core.MutationContext) ([]byte, error)
}

// RawHeader preserva a ordem, a grafia, as duplicatas e os bytes exatos dos
// cabeçalhos após os dois-pontos. Value inclui, portanto, qualquer espaço inicial.
type RawHeader struct {
	Name  string
	Value string
}

type NullByteHostProbe struct{}
type HostWhitespaceProbe struct{}
type HostTrailingDotProbe struct{}
type ExplicitPortProbe struct{}
type AbsoluteFormProbe struct{}
type CLTEProbe struct{}
type TECLProbe struct{}

func DefaultHTTPMutations() []HTTPMutation {
	return []HTTPMutation{
		NullByteHostProbe{},
		HostWhitespaceProbe{},
		HostTrailingDotProbe{},
		ExplicitPortProbe{},
		AbsoluteFormProbe{},
	}
}

func ExperimentalFramingMutations() []HTTPMutation {
	return []HTTPMutation{CLTEProbe{}, TECLProbe{}}
}

func (NullByteHostProbe) Name() string    { return "NullByteHostProbe" }
func (HostWhitespaceProbe) Name() string  { return "HostWhitespaceProbe" }
func (HostTrailingDotProbe) Name() string { return "HostTrailingDotProbe" }
func (ExplicitPortProbe) Name() string    { return "ExplicitPortProbe" }
func (AbsoluteFormProbe) Name() string    { return "AbsoluteFormProbe" }
func (CLTEProbe) Name() string            { return "CLTEProbe" }
func (TECLProbe) Name() string            { return "TECLProbe" }

func (NullByteHostProbe) Description() string { return "byte NUL acrescentado ao valor do campo Host" }
func (HostWhitespaceProbe) Description() string {
	return "espaço adicional no início do valor do campo Host"
}
func (HostTrailingDotProbe) Description() string {
	return "ponto final da raiz DNS acrescentado à autoridade Host"
}
func (ExplicitPortProbe) Description() string {
	return "porta TCP explícita acrescentada ao Host quando altera os bytes da autoridade"
}
func (AbsoluteFormProbe) Description() string {
	return "alvo da requisição em formato absoluto, preservando a mesma autoridade Host"
}
func (CLTEProbe) Description() string {
	return "requisição contendo Content-Length e Transfer-Encoding chunked (hipótese CL.TE)"
}
func (TECLProbe) Description() string {
	return "requisição contendo Content-Length e Transfer-Encoding chunked (hipótese TE.CL)"
}

func probeApplicable(ctx core.MutationContext) bool {
	return ctx.DialHost != "" && ctx.HTTPAuthority != "" && ctx.Baseline.Complete && ctx.BlockDecision.Blocked && len(ctx.ProviderCandidates) > 0
}

func framingProbeApplicable(ctx core.MutationContext) bool {
	return ctx.DialHost != "" && ctx.HTTPAuthority != "" && ctx.Baseline.Complete && ctx.BlockDecision.Blocked
}

func (NullByteHostProbe) Applicability(ctx core.MutationContext) bool    { return probeApplicable(ctx) }
func (HostWhitespaceProbe) Applicability(ctx core.MutationContext) bool  { return probeApplicable(ctx) }
func (HostTrailingDotProbe) Applicability(ctx core.MutationContext) bool { return probeApplicable(ctx) }
func (ExplicitPortProbe) Applicability(ctx core.MutationContext) bool {
	if !probeApplicable(ctx) {
		return false
	}
	host, port, err := mutationEndpoint(ctx)
	return err == nil && ctx.HTTPAuthority != net.JoinHostPort(host, strconv.Itoa(port))
}
func (AbsoluteFormProbe) Applicability(ctx core.MutationContext) bool { return probeApplicable(ctx) }
func (CLTEProbe) Applicability(ctx core.MutationContext) bool         { return framingProbeApplicable(ctx) }
func (TECLProbe) Applicability(ctx core.MutationContext) bool         { return framingProbeApplicable(ctx) }

func (probe NullByteHostProbe) Build(ctx core.MutationContext) ([]byte, error) {
	host := mutationHost(ctx)
	return buildRawRequest("GET", "/", standardRawHeaders(host+"\x00", "close"), nil)
}

func (probe HostWhitespaceProbe) Build(ctx core.MutationContext) ([]byte, error) {
	host := mutationHost(ctx)
	headers := standardRawHeaders(host, "close")
	headers[0].Value = "  " + host
	return buildRawRequest("GET", "/", headers, nil)
}

func (probe HostTrailingDotProbe) Build(ctx core.MutationContext) ([]byte, error) {
	host := mutationHost(ctx)
	name, port, err := net.SplitHostPort(host)
	if err == nil {
		host = net.JoinHostPort(strings.TrimSuffix(name, ".")+".", port)
	} else {
		host = strings.TrimSuffix(host, ".") + "."
	}
	return buildRawRequest("GET", "/", standardRawHeaders(host, "close"), nil)
}

func (probe ExplicitPortProbe) Build(ctx core.MutationContext) ([]byte, error) {
	host, port, err := mutationEndpoint(ctx)
	if err != nil {
		return nil, err
	}
	return buildRawRequest("GET", "/", standardRawHeaders(net.JoinHostPort(host, strconv.Itoa(port)), "close"), nil)
}

func (probe AbsoluteFormProbe) Build(ctx core.MutationContext) ([]byte, error) {
	authority := mutationHost(ctx)
	target := fmt.Sprintf("%s://%s/", ctx.Scheme, authority)
	return buildRawRequest("GET", target, standardRawHeaders(authority, "close"), nil)
}

func (probe CLTEProbe) Build(ctx core.MutationContext) ([]byte, error) {
	terminator := encodeChunkedBody(nil)
	body := append(append([]byte(nil), terminator...), byte('X'))
	headers := framingHeaders(mutationHost(ctx), strconv.Itoa(len(body)), true)
	return buildRawRequest("POST", "/", headers, body)
}

func (probe TECLProbe) Build(ctx core.MutationContext) ([]byte, error) {
	chunkData := []byte("Z")
	body := encodeChunkedBody(chunkData)
	contentLengthPrefix := fmt.Appendf(nil, "%x\r\n%s", len(chunkData), chunkData)
	headers := framingHeaders(mutationHost(ctx), strconv.Itoa(len(contentLengthPrefix)), true)
	return buildRawRequest("POST", "/", headers, body)
}

func (probe NullByteHostProbe) BuildMutation(ctx core.MutationContext) ([]byte, error) {
	return probe.Build(ctx)
}
func (probe HostWhitespaceProbe) BuildMutation(ctx core.MutationContext) ([]byte, error) {
	return probe.Build(ctx)
}
func (probe HostTrailingDotProbe) BuildMutation(ctx core.MutationContext) ([]byte, error) {
	return probe.Build(ctx)
}
func (probe ExplicitPortProbe) BuildMutation(ctx core.MutationContext) ([]byte, error) {
	return probe.Build(ctx)
}
func (probe AbsoluteFormProbe) BuildMutation(ctx core.MutationContext) ([]byte, error) {
	return probe.Build(ctx)
}
func (probe CLTEProbe) BuildMutation(ctx core.MutationContext) ([]byte, error) {
	return probe.Build(ctx)
}
func (probe TECLProbe) BuildMutation(ctx core.MutationContext) ([]byte, error) {
	return probe.Build(ctx)
}

func normalGETControl(ctx core.MutationContext) ([]byte, error) {
	return buildRawRequest("GET", "/", standardRawHeaders(mutationHost(ctx), "close"), nil)
}
func (NullByteHostProbe) BuildControl(ctx core.MutationContext) ([]byte, error) {
	return normalGETControl(ctx)
}
func (HostWhitespaceProbe) BuildControl(ctx core.MutationContext) ([]byte, error) {
	return normalGETControl(ctx)
}
func (HostTrailingDotProbe) BuildControl(ctx core.MutationContext) ([]byte, error) {
	return normalGETControl(ctx)
}
func (ExplicitPortProbe) BuildControl(ctx core.MutationContext) ([]byte, error) {
	return normalGETControl(ctx)
}
func (AbsoluteFormProbe) BuildControl(ctx core.MutationContext) ([]byte, error) {
	return normalGETControl(ctx)
}
func (CLTEProbe) BuildControl(ctx core.MutationContext) ([]byte, error) {
	body := []byte("X")
	return buildRawRequest("POST", "/", framingHeaders(mutationHost(ctx), strconv.Itoa(len(body)), false), body)
}
func (TECLProbe) BuildControl(ctx core.MutationContext) ([]byte, error) {
	body := []byte("Z")
	return buildRawRequest("POST", "/", framingHeaders(mutationHost(ctx), strconv.Itoa(len(body)), false), body)
}

func buildRawRequest(method, target string, headers []RawHeader, body []byte) ([]byte, error) {
	if method == "" || target == "" || len(headers) == 0 {
		return nil, fmt.Errorf("método, destino e cabeçalhos são obrigatórios")
	}
	var buffer bytes.Buffer
	fmt.Fprintf(&buffer, "%s %s HTTP/1.1\r\n", method, target)
	for _, header := range headers {
		if header.Name == "" || strings.ContainsAny(header.Name, "\r\n:") || strings.ContainsAny(header.Value, "\r\n") {
			return nil, fmt.Errorf("cabeçalho bruto (raw) inválido")
		}
		fmt.Fprintf(&buffer, "%s:%s\r\n", header.Name, header.Value)
	}
	buffer.WriteString("\r\n")
	buffer.Write(body)
	return buffer.Bytes(), nil
}

func standardRawHeaders(host, connection string) []RawHeader {
	return []RawHeader{
		{Name: "Host", Value: " " + host},
		{Name: "User-Agent", Value: " SubdomainAbber-Mutator/experimental"},
		{Name: "Connection", Value: " " + connection},
	}
}

func framingHeaders(host, contentLength string, chunked bool) []RawHeader {
	headers := []RawHeader{
		{Name: "Host", Value: " " + host},
		{Name: "User-Agent", Value: " SubdomainAbber-Mutator/experimental"},
		{Name: "Connection", Value: " keep-alive"},
		{Name: "Content-Type", Value: " application/octet-stream"},
		{Name: "Content-Length", Value: " " + contentLength},
	}
	if chunked {
		headers = append(headers, RawHeader{Name: "Transfer-Encoding", Value: " chunked"})
	}
	return headers
}

func encodeChunkedBody(data []byte) []byte {
	if len(data) == 0 {
		return []byte("0\r\n\r\n")
	}
	return fmt.Appendf(nil, "%x\r\n%s\r\n0\r\n\r\n", len(data), data)
}

func mutationHost(ctx core.MutationContext) string {
	return ctx.HTTPAuthority
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func differentialEvidenceType() string {
	return "HTTP_MUTATION_DIFFERENTIAL"
}
