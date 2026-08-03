package verifiers

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
)

type AzureBlobVerifier struct {
	client *http.Client
}

func NewAzureBlobVerifier(cfg Config) *AzureBlobVerifier {
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &AzureBlobVerifier{client: client}
}

func (v *AzureBlobVerifier) Name() string {
	return "Azure Blob Storage"
}

func (v *AzureBlobVerifier) Verify(ctx context.Context, analysis *core.HostAnalysis) (*core.VerificationResult, error) {
	if !hasProviderCNAME(analysis, "blob.core.windows.net") {
		return nil, nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+analysis.Host+"/?comp=list", nil)
	if err != nil {
		return nil, err
	}

	resp, err := v.client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		bodyStr := string(body)

		if resp.StatusCode == 404 && strings.Contains(bodyStr, "The specified account does not exist.") {
			return &core.VerificationResult{
				Provider:   v.Name(),
				Verified:   true,
				Confidence: 100,
				Evidence:   "API do Azure Blob retornou AccountNotFound.",
			}, nil
		}

		if resp.StatusCode == 403 && (strings.Contains(bodyStr, "PublicAccessNotPermitted") || strings.Contains(bodyStr, "AuthenticationFailed")) {
			analysis.AddEvidence(core.Evidence{
				Type:        "CLOUD_AZURE_BLOB_PRIVATE",
				Source:      v.Name(),
				Description: "A conta de armazenamento existe, mas retornou erro de permissão (não é vulnerável a takeover).",
				Weight:      50,
				Confidence:  100,
				IsNegative:  true,
			})
			return &core.VerificationResult{
				Provider:   v.Name(),
				Verified:   false,
				Confidence: 100,
				Evidence:   "A conta de armazenamento retornou AuthenticationFailed/PublicAccessNotPermitted; portanto, já existe e não está órfã.",
			}, nil
		}

		if resp.StatusCode == 200 && strings.Contains(bodyStr, "<EnumerationResults") {
			analysis.AddEvidence(core.Evidence{
				Type:        "CLOUD_AZURE_BLOB_LISTABLE",
				Source:      v.Name(),
				Description: "O contêiner ou a conta do Azure Blob permite a listagem pública de arquivos.",
				Weight:      70,
				Confidence:  100,
			})
		}
	}

	return nil, nil
}
