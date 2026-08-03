package verifiers

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
)

type GCSBucketVerifier struct {
	client *http.Client
}

func NewGCSBucketVerifier(cfg Config) *GCSBucketVerifier {
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &GCSBucketVerifier{client: client}
}

func (v *GCSBucketVerifier) Name() string {
	return "Google Cloud Storage"
}

func (v *GCSBucketVerifier) Verify(ctx context.Context, analysis *core.HostAnalysis) (*core.VerificationResult, error) {
	if !hasProviderCNAME(analysis, "storage.googleapis.com") {
		return nil, nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+analysis.Host, nil)
	if err != nil {
		return nil, err
	}

	resp, err := v.client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		bodyStr := string(body)

		if resp.StatusCode == 404 && strings.Contains(bodyStr, "<Code>NoSuchBucket</Code>") {
			return &core.VerificationResult{
				Provider:   v.Name(),
				Verified:   true,
				Confidence: 100,
				Evidence:   "API pública do GCS retornou <Code>NoSuchBucket</Code>",
			}, nil
		}

		if resp.StatusCode == 403 && strings.Contains(bodyStr, "<Code>AccessDenied</Code>") {
			analysis.AddEvidence(core.Evidence{
				Type:        "CLOUD_GCS_PRIVATE",
				Source:      v.Name(),
				Description: "O bucket GCS existe, mas retornou AccessDenied (não é vulnerável a takeover).",
				Weight:      50,
				Confidence:  100,
				IsNegative:  true,
			})
			return &core.VerificationResult{
				Provider:   v.Name(),
				Verified:   false,
				Confidence: 100,
				Evidence:   "O bucket GCS retornou AccessDenied; portanto, já existe e não está órfão.",
			}, nil
		}

		if resp.StatusCode == 200 && strings.Contains(bodyStr, "<ListBucketResult") {
			analysis.AddEvidence(core.Evidence{
				Type:        "CLOUD_GCS_LISTABLE",
				Source:      v.Name(),
				Description: "O bucket GCS permite a listagem pública de arquivos.",
				Weight:      70,
				Confidence:  100,
			})
		}
	}

	return nil, nil
}
