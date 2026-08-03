package evidence

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/pkg/signatures"
)

// TLSDialer abstrai a conexão TLS para permitir testes locais de regressão.
type TLSDialer interface {
	DialTLSContext(ctx context.Context, network, addr string, config *tls.Config) (*tls.ConnectionState, error)
}

// DefaultTLSDialer implementa o discador de rede usado em produção.
type DefaultTLSDialer struct {
	Timeout time.Duration
}

func (d *DefaultTLSDialer) DialTLSContext(ctx context.Context, network, addr string, config *tls.Config) (*tls.ConnectionState, error) {
	dialer := &net.Dialer{
		Timeout: d.Timeout,
	}
	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, config)
	tlsConn.SetDeadline(time.Now().Add(d.Timeout))

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}

	state := tlsConn.ConnectionState()
	return &state, nil
}

// TLSCollector coleta metadados do certificado apresentado pelo host.
type TLSCollector struct {
	sigs    []signatures.Fingerprint
	dialer  TLSDialer
	timeout time.Duration
	limiter interface{ Wait(context.Context) error }
}

func NewTLSCollector(sigs []signatures.Fingerprint, timeout time.Duration) *TLSCollector {
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	return &TLSCollector{
		sigs:    sigs,
		dialer:  &DefaultTLSDialer{Timeout: timeout},
		timeout: timeout,
	}
}

// SetDialer permite usar um discador simulado nos benchmarks L1 e L3.
func (c *TLSCollector) SetDialer(dialer TLSDialer) {
	c.dialer = dialer
}

func (c *TLSCollector) SetRequestLimiter(limiter interface{ Wait(context.Context) error }) {
	c.limiter = limiter
}

func (c *TLSCollector) Collect(ctx context.Context, analysis *core.HostAnalysis) error {
	if len(analysis.DNS.A) == 0 && len(analysis.DNS.AAAA) == 0 {
		return nil
	}
	analysis.AddTestedVector("TLS")
	if c.limiter != nil {
		if err := c.limiter.Wait(ctx); err != nil {
			return err
		}
	}

	config := &tls.Config{
		// A coleta precisa observar certificados expirados ou com nome divergente.
		// Por isso a negociação não valida a cadeia; nenhuma evidência abaixo deve
		// ser descrita como prova criptográfica de identidade.
		InsecureSkipVerify: true,
		ServerName:         analysis.Host,
	}

	// Conecta à porta 443 por meio da abstração de transporte.
	state, err := c.dialer.DialTLSContext(ctx, "tcp", net.JoinHostPort(analysis.Host, "443"), config)
	if err != nil || state == nil {
		return nil // Falha na conexão ou na negociação TLS
	}
	if len(state.PeerCertificates) == 0 {
		return nil // A conexão não apresentou um certificado para análise.
	}
	cert := state.PeerCertificates[0] // Certificado folha.
	if cert == nil {
		return nil
	}

	issuer := cert.Issuer.CommonName
	if issuer == "" && len(cert.Issuer.Organization) > 0 {
		issuer = cert.Issuer.Organization[0]
	}

	subject := cert.Subject.CommonName
	if subject == "" && len(cert.Subject.Organization) > 0 {
		subject = cert.Subject.Organization[0]
	}

	sans := cert.DNSNames
	expiresAt := cert.NotAfter
	hostMatch := certificateCoversHost(cert, analysis.Host)

	// Prepara os metadados básicos.
	metadata := map[string]string{
		"tls_issuer":           issuer,
		"tls_subject":          subject,
		"tls_sans":             strings.Join(sans, ", "),
		"tls_expires_at":       expiresAt.Format(time.RFC3339),
		"tls_hostname_match":   fmt.Sprintf("%t", hostMatch),
		"tls_chain_validation": "not_performed",
	}

	// Procura uma assinatura TLS associada ao provedor.
	matchedProvider := false
	certText := strings.ToLower(issuer + " " + subject + " " + strings.Join(sans, " "))
	for _, sig := range c.sigs {
		for _, fp := range sig.TLSFingerprints {
			normalizedFingerprint := strings.ToLower(strings.TrimSpace(fp))
			if normalizedFingerprint == "" {
				continue
			}
			if strings.Contains(certText, normalizedFingerprint) {
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
					Type:        "TLS_PROVIDER_MATCH",
					Source:      sig.Service,
					Description: fmt.Sprintf("O certificado apresentado contém um texto associado a %q no emissor, assunto ou SAN; essa correspondência não comprova identidade nem confiança da cadeia", sig.Service),
					Weight:      0,
					Confidence:  confidence,
					Metadata:    metadata,
				})
				matchedProvider = true
				break
			}
		}
	}

	// Registra a expiração do certificado apresentado.
	if time.Now().After(expiresAt) {
		analysis.AddEvidence(core.Evidence{
			Type:        "TLS_EXPIRED",
			Source:      "TLS",
			Description: fmt.Sprintf("O certificado apresentado expirou em %s; a expiração isolada não comprova abandono nem takeover", expiresAt.Format("2006-01-02")),
			Weight:      0,
			Confidence:  100,
			Metadata:    metadata,
		})
	}

	// Identifica autoemissão pela igualdade entre emissor e assunto.
	if issuer != "" && issuer == subject {
		analysis.AddEvidence(core.Evidence{
			Type:        "TLS_SELF_SIGNED",
			Source:      "TLS",
			Description: "O emissor e o assunto do certificado apresentado coincidem; isso indica autoemissão, mas a assinatura e a cadeia de confiança não foram verificadas",
			Weight:      0,
			Confidence:  80,
			Metadata:    metadata,
		})
	}

	// Verifica TLS_MISMATCH pelas identidades SAN do certificado. VerifyHostname
	// aplica as regras de curinga de certificados e ignora o Common Name legado.
	if !hostMatch {
		analysis.AddEvidence(core.Evidence{
			Type:        "TLS_MISMATCH",
			Source:      "TLS",
			Description: "O nome do host não corresponde a nenhuma identidade SAN válida do certificado apresentado; isso não comprova takeover",
			Weight:      0,
			Confidence:  100,
			Metadata:    metadata,
		})
	} else if !matchedProvider {
		// A correspondência de nome é apenas contextual: o coletor não validou
		// a assinatura, a cadeia de confiança nem o estado de revogação.
		analysis.AddEvidence(core.Evidence{
			Type:        "TLS_SAN_MATCH",
			Source:      "TLS",
			Description: "O nome do host corresponde a um SAN do certificado apresentado; a assinatura, a cadeia de confiança e a revogação não foram verificadas",
			Weight:      0,
			Confidence:  100,
			IsNegative:  true,
			Metadata:    metadata,
		})
	}

	return nil
}

// certificateCoversHost verifica somente a correspondência de hostname do
// certificado apresentado. Ela não valida assinatura, cadeia ou revogação.
func certificateCoversHost(cert *x509.Certificate, host string) bool {
	if cert == nil {
		return false
	}
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" {
		return false
	}
	return cert.VerifyHostname(host) == nil
}
