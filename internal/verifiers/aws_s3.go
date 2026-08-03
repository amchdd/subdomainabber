package verifiers

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
)

type AWSVerifier struct {
	client *http.Client
	config Config
}

func NewAWSVerifier(cfg Config) *AWSVerifier {
	return &AWSVerifier{client: cfg.Client, config: cfg}
}

func (v *AWSVerifier) Name() string {
	return "AWS S3"
}

func (v *AWSVerifier) Verify(ctx context.Context, analysis *core.HostAnalysis) (*core.VerificationResult, error) {
	if !hasS3CNAME(analysis) {
		return nil, nil
	}

	client := v.client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}

	// Verifica a assinatura de takeover e a possibilidade de listagem.
	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+analysis.Host, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		bodyStr := string(body)

		// Verifica takeover (NoSuchBucket).
		if resp.StatusCode == 404 && strings.Contains(bodyStr, "<Code>NoSuchBucket</Code>") {
			return &core.VerificationResult{
				Provider:   v.Name(),
				Verified:   true,
				Confidence: 100,
				Evidence:   "API pública do S3 retornou <Code>NoSuchBucket</Code>",
			}, nil
		}

		// Verifica recurso privado (AccessDenied).
		if resp.StatusCode == 403 && strings.Contains(bodyStr, "<Code>AccessDenied</Code>") {
			analysis.AddEvidence(core.Evidence{
				Type:        "CLOUD_S3_PRIVATE",
				Source:      "AWS S3",
				Description: "O bucket S3 existe, mas retornou AccessDenied (não é vulnerável a takeover).",
				Weight:      50,
				Confidence:  100,
				IsNegative:  true,
			})
			return &core.VerificationResult{
				Provider:   v.Name(),
				Verified:   false,
				Confidence: 100,
				Evidence:   "O bucket S3 retornou AccessDenied; portanto, já existe e não está órfão.",
			}, nil
		}

		// Verifica possibilidade de listagem.
		if resp.StatusCode == 200 && strings.Contains(bodyStr, "<ListBucketResult") {
			analysis.AddEvidence(core.Evidence{
				Type:        "CLOUD_S3_LISTABLE",
				Source:      "AWS S3",
				Description: "O bucket S3 permite a listagem pública de arquivos.",
				Weight:      70,
				Confidence:  100,
			})
		}
	}

	// Verifica a possibilidade de gravação pela ACL.
	reqAcl, err := http.NewRequestWithContext(ctx, "GET", "http://"+analysis.Host+"/?acl", nil)
	if err == nil {
		respAcl, errAcl := client.Do(reqAcl)
		if errAcl == nil {
			defer respAcl.Body.Close()
			bodyAcl, _ := io.ReadAll(io.LimitReader(respAcl.Body, 1<<20))
			aclStr := string(bodyAcl)

			if respAcl.StatusCode == 200 && strings.Contains(aclStr, "<AccessControlPolicy") {
				// Verificação simples de AllUsers combinado com WRITE ou FULL_CONTROL.
				if strings.Contains(aclStr, "http://acs.amazonaws.com/groups/global/AllUsers") &&
					(strings.Contains(aclStr, "<Permission>WRITE</Permission>") || strings.Contains(aclStr, "<Permission>FULL_CONTROL</Permission>")) {
					analysis.AddEvidence(core.Evidence{
						Type:        "CLOUD_S3_WRITABLE",
						Source:      "AWS S3",
						Description: "O bucket S3 permite gravação pública baseada em ACL (WRITE/FULL_CONTROL).",
						Weight:      90,
						Confidence:  100,
					})
				}
			}
		}
	}

	return nil, nil
}
