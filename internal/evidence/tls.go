package evidence

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/dns"
	"github.com/amchdd/subdomainabber/internal/domainutil"
	"github.com/amchdd/subdomainabber/pkg/signatures"
)

const maxSANCandidates = 64

type TLSDialer interface {
	DialTLSContext(context.Context, string, string, *tls.Config) (*tls.ConnectionState, error)
}

type DefaultTLSDialer struct {
	Timeout time.Duration
}

func (dialer *DefaultTLSDialer) DialTLSContext(ctx context.Context, network, addr string, config *tls.Config) (*tls.ConnectionState, error) {
	conn, err := (&net.Dialer{Timeout: dialer.Timeout}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	tlsConn := tls.Client(conn, config)
	_ = tlsConn.SetDeadline(time.Now().Add(dialer.Timeout))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	state := tlsConn.ConnectionState()
	return &state, nil
}

type TLSCollector struct {
	sigs        []signatures.Fingerprint
	dialer      TLSDialer
	limiter     interface{ Wait(context.Context) error }
	checkSNI    bool
	altSNI      bool
	discoverSAN bool
	sanRoots    map[string]struct{}
	sniName     func(string) string
}

func NewTLSCollector(sigs []signatures.Fingerprint, timeout time.Duration) *TLSCollector {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &TLSCollector{
		sigs: sigs, dialer: &DefaultTLSDialer{Timeout: timeout},
		checkSNI: true, discoverSAN: true, sanRoots: make(map[string]struct{}), sniName: randomSNIName,
	}
}

func (collector *TLSCollector) SetDialer(dialer TLSDialer) {
	if dialer != nil {
		collector.dialer = dialer
	}
}

func (collector *TLSCollector) SetRequestLimiter(limiter interface{ Wait(context.Context) error }) {
	collector.limiter = limiter
}

func (collector *TLSCollector) EnableSNI(enabled bool) {
	collector.checkSNI = enabled
	collector.altSNI = enabled
}

func (collector *TLSCollector) EnableAlternateSNI(enabled bool) {
	collector.checkSNI = true
	collector.altSNI = enabled
}

func (collector *TLSCollector) EnableSANDiscovery(enabled bool) {
	collector.discoverSAN = enabled
}

func (collector *TLSCollector) SetSANRoots(roots []string) {
	collector.sanRoots = make(map[string]struct{}, len(roots))
	for _, root := range roots {
		if normalized, err := domainutil.NormalizeHostname(root); err == nil {
			collector.sanRoots[normalized] = struct{}{}
		}
	}
}

func (collector *TLSCollector) Collect(ctx context.Context, analysis *core.HostAnalysis) error {
	if analysis == nil || (len(analysis.DNS.A) == 0 && len(analysis.DNS.AAAA) == 0) {
		return nil
	}
	analysis.AddTestedVector("TLS")
	endpoint := tlsEndpoint(analysis)
	if err := collector.wait(ctx); err != nil {
		return err
	}
	observation, cert, err := collector.observe(ctx, endpoint, analysis.Host, "baseline")
	if err != nil || cert == nil {
		return nil
	}

	providers := collector.providers(cert)
	if len(providers) > 0 {
		observation.Provider = providers[0].Service
	}
	analysis.SetTLS(observation)
	metadata := tlsMetadata(observation, certificateCoversHost(cert, analysis.Host))
	analysis.AddEvidence(core.Evidence{
		Type: "TLS_CERTIFICATE_OBSERVED", Source: "TLS",
		Description: "O certificado folha foi registrado para comparação histórica.",
		Weight:      0, Confidence: 100, Metadata: metadata,
	})
	collector.addProviderEvidence(analysis, providers, metadata)
	collector.addCertificateState(analysis, cert, observation, metadata)
	collector.addDrift(analysis, metadata)
	collector.addSANCandidates(analysis, observation)
	if collector.checkSNI {
		if err := collector.inspectSNI(ctx, analysis, endpoint, observation); err != nil {
			return err
		}
	}
	return nil
}

func (collector *TLSCollector) observe(ctx context.Context, endpoint, serverName, mode string) (core.TLSObservation, *x509.Certificate, error) {
	config := &tls.Config{InsecureSkipVerify: true, ServerName: serverName} //nolint:gosec
	state, err := collector.dialer.DialTLSContext(ctx, "tcp", endpoint, config)
	if err != nil || state == nil || len(state.PeerCertificates) == 0 || state.PeerCertificates[0] == nil {
		return core.TLSObservation{}, nil, err
	}
	cert := state.PeerCertificates[0]
	observation := core.TLSObservation{
		Mode: mode, ServerName: serverName, Fingerprint: certificateFingerprint(cert),
		Issuer: issuerName(cert), Subject: subjectName(cert), SANs: normalizedSANs(cert.DNSNames), NotAfter: cert.NotAfter,
	}
	return observation, cert, nil
}

func (collector *TLSCollector) wait(ctx context.Context) error {
	if collector.limiter == nil {
		return nil
	}
	return collector.limiter.Wait(ctx)
}

func (collector *TLSCollector) providers(cert *x509.Certificate) []signatures.Fingerprint {
	text := strings.ToLower(issuerName(cert) + " " + subjectName(cert) + " " + strings.Join(cert.DNSNames, " "))
	var matches []signatures.Fingerprint
	for _, sig := range collector.sigs {
		for _, value := range sig.TLSFingerprints {
			value = strings.ToLower(strings.TrimSpace(value))
			if value != "" && strings.Contains(text, value) {
				matches = append(matches, sig)
				break
			}
		}
	}
	return matches
}

func (collector *TLSCollector) addProviderEvidence(analysis *core.HostAnalysis, providers []signatures.Fingerprint, metadata map[string]string) {
	for _, sig := range providers {
		confidence := sig.TLSConfidence
		if confidence == 0 {
			confidence = sig.Confidence
		}
		if confidence <= 0 {
			confidence = 50
		}
		if confidence > 70 {
			confidence = 70
		}
		analysis.AddEvidence(core.Evidence{
			Type: "TLS_PROVIDER_MATCH", Source: sig.Service,
			Description: fmt.Sprintf("O certificado contém texto associado a %q; a cadeia de confiança não foi validada.", sig.Service),
			Weight:      0, Confidence: confidence, Metadata: metadata,
		})
	}
}

func (collector *TLSCollector) addCertificateState(analysis *core.HostAnalysis, cert *x509.Certificate, observation core.TLSObservation, metadata map[string]string) {
	if time.Now().After(observation.NotAfter) {
		analysis.AddEvidence(core.Evidence{
			Type: "TLS_EXPIRED", Source: "TLS",
			Description: fmt.Sprintf("O certificado apresentado expirou em %s; a expiração isolada não comprova abandono.", observation.NotAfter.Format("2006-01-02")),
			Weight:      0, Confidence: 100, Metadata: metadata,
		})
	}
	if observation.Issuer != "" && observation.Issuer == observation.Subject {
		analysis.AddEvidence(core.Evidence{
			Type: "TLS_SELF_SIGNED", Source: "TLS",
			Description: "O emissor e o assunto coincidem; a assinatura e a cadeia não foram validadas.",
			Weight:      0, Confidence: 80, Metadata: metadata,
		})
	}
	if !certificateCoversHost(cert, analysis.Host) {
		analysis.AddEvidence(core.Evidence{
			Type: "TLS_MISMATCH", Source: "TLS",
			Description: "O hostname não corresponde às identidades SAN do certificado apresentado.",
			Weight:      0, Confidence: 100, Metadata: metadata,
		})
	} else if observation.Provider == "" {
		analysis.AddEvidence(core.Evidence{
			Type: "TLS_SAN_MATCH", Source: "TLS",
			Description: "O hostname corresponde a um SAN; a cadeia de confiança e a revogação não foram verificadas.",
			Weight:      0, Confidence: 100, IsNegative: true, Metadata: metadata,
		})
	}
}

func (collector *TLSCollector) inspectSNI(ctx context.Context, analysis *core.HostAnalysis, endpoint string, baseline core.TLSObservation) error {
	analysis.AddTestedVector("SNI")
	root := dns.ExtractRootDomain(analysis.Host)
	probes := []struct{ mode, name string }{{mode: "no_sni"}}
	if collector.altSNI {
		probes = append(probes, struct{ mode, name string }{mode: "alternate_sni", name: collector.sniName(root)})
	}
	for _, probe := range probes {
		if err := collector.wait(ctx); err != nil {
			return err
		}
		observation, _, err := collector.observe(ctx, endpoint, probe.name, probe.mode)
		if err != nil || observation.Fingerprint == "" {
			continue
		}
		analysis.AddSNIVariant(observation)
		if observation.Fingerprint == baseline.Fingerprint {
			continue
		}
		analysis.AddEvidence(core.Evidence{
			Type: "SNI_CERT_MISMATCH", Source: probe.mode,
			Description: "O mesmo IP apresentou outro certificado quando o SNI mudou ou foi omitido.",
			Weight:      0, Confidence: 100,
			Metadata: map[string]string{
				"baseline_fingerprint": baseline.Fingerprint, "variant_fingerprint": observation.Fingerprint,
				"server_name": probe.name, "variant_sans": strings.Join(observation.SANs, ","),
			},
		})
	}
	return nil
}

func (collector *TLSCollector) addSANCandidates(analysis *core.HostAnalysis, observation core.TLSObservation) {
	if !collector.discoverSAN && len(collector.sanRoots) == 0 {
		return
	}
	root := dns.ExtractRootDomain(analysis.Host)
	if len(collector.sanRoots) > 0 {
		analysis.AddTestedVector("TLS_SAN_PIVOT")
	} else {
		analysis.AddTestedVector("TLS_SAN_DISCOVERY")
	}
	added := 0
	for _, san := range observation.SANs {
		if added >= maxSANCandidates || strings.HasPrefix(san, "*.") || strings.EqualFold(san, analysis.Host) || !collector.allowedSAN(san, root) {
			continue
		}
		analysis.AddSANCandidate(san)
		analysis.AddEvidence(core.Evidence{
			Type: "TLS_SAN_CANDIDATE", Source: "TLS",
			Description: "Um SAN relacionado foi registrado como candidato passivo.",
			Weight:      0, Confidence: 100, Metadata: map[string]string{"host": san},
		})
		added++
	}
}

func (collector *TLSCollector) allowedSAN(host, root string) bool {
	if len(collector.sanRoots) == 0 {
		return root != "" && dns.ExtractRootDomain(host) == root
	}
	for root := range collector.sanRoots {
		if host == root || strings.HasSuffix(host, "."+root) {
			return true
		}
	}
	return false
}

func (collector *TLSCollector) addDrift(analysis *core.HostAnalysis, current map[string]string) {
	var previous map[string]string
	for _, evidence := range analysis.PreviousEvidences {
		if evidence.Type == "TLS_CERTIFICATE_OBSERVED" {
			previous = evidence.Metadata
			break
		}
	}
	if previous == nil || previous["tls_fingerprint"] == "" || previous["tls_fingerprint"] == current["tls_fingerprint"] {
		return
	}
	var changed []string
	for _, field := range []string{"tls_issuer", "tls_sans", "tls_provider"} {
		if previous[field] != current[field] {
			changed = append(changed, strings.TrimPrefix(field, "tls_"))
		}
	}
	if len(changed) == 0 {
		return
	}
	analysis.AddEvidence(core.Evidence{
		Type: "TLS_CERTIFICATE_DRIFT", Source: "HISTORY",
		Description: "Issuer, SAN ou provider do certificado mudou desde a coleta anterior.",
		Weight:      0, Confidence: 100,
		Metadata: map[string]string{
			"changed":              strings.Join(changed, ","),
			"previous_fingerprint": previous["tls_fingerprint"], "current_fingerprint": current["tls_fingerprint"],
			"previous_issuer": previous["tls_issuer"], "current_issuer": current["tls_issuer"],
			"previous_sans": previous["tls_sans"], "current_sans": current["tls_sans"],
			"previous_provider": previous["tls_provider"], "current_provider": current["tls_provider"],
		},
	})
}

func tlsEndpoint(analysis *core.HostAnalysis) string {
	host := analysis.Host
	if len(analysis.DNS.A) > 0 {
		host = analysis.DNS.A[0]
	} else if len(analysis.DNS.AAAA) > 0 {
		host = analysis.DNS.AAAA[0]
	}
	return net.JoinHostPort(host, "443")
}

func tlsMetadata(observation core.TLSObservation, hostMatch bool) map[string]string {
	return map[string]string{
		"tls_fingerprint": observation.Fingerprint,
		"tls_issuer":      observation.Issuer, "tls_subject": observation.Subject,
		"tls_sans": strings.Join(observation.SANs, ","), "tls_expires_at": observation.NotAfter.Format(time.RFC3339),
		"tls_provider": observation.Provider, "tls_hostname_match": fmt.Sprintf("%t", hostMatch),
		"tls_chain_validation": "not_performed",
	}
}

func certificateFingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	data := cert.Raw
	if len(data) == 0 {
		data = []byte(issuerName(cert) + "|" + subjectName(cert) + "|" + strings.Join(normalizedSANs(cert.DNSNames), ",") + "|" + cert.NotAfter.UTC().Format(time.RFC3339))
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func normalizedSANs(values []string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, value := range values {
		value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
		if value == "" {
			continue
		}
		if strings.HasPrefix(value, "*.") {
			if _, err := domainutil.NormalizeHostname(strings.TrimPrefix(value, "*.")); err != nil {
				continue
			}
		} else if _, err := domainutil.NormalizeHostname(value); err != nil {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func issuerName(cert *x509.Certificate) string {
	if cert.Issuer.CommonName != "" {
		return cert.Issuer.CommonName
	}
	if len(cert.Issuer.Organization) > 0 {
		return cert.Issuer.Organization[0]
	}
	return ""
}

func subjectName(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	if len(cert.Subject.Organization) > 0 {
		return cert.Subject.Organization[0]
	}
	return ""
}

func randomSNIName(root string) string {
	buffer := make([]byte, 8)
	if _, err := rand.Read(buffer); err != nil {
		return "sni-probe.invalid"
	}
	if root == "" {
		root = "invalid"
	}
	return hex.EncodeToString(buffer) + "." + root
}

func certificateCoversHost(cert *x509.Certificate, host string) bool {
	if cert == nil {
		return false
	}
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	return host != "" && cert.VerifyHostname(host) == nil
}
