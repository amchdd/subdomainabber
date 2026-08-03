package verifiers

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
)

type ShopifyVerifier struct {
	client *http.Client
}

func NewShopifyVerifier(cfg Config) *ShopifyVerifier {
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &ShopifyVerifier{
		client: client,
	}
}

func (v *ShopifyVerifier) Name() string {
	return "Shopify"
}

func (v *ShopifyVerifier) Verify(ctx context.Context, analysis *core.HostAnalysis) (*core.VerificationResult, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+analysis.Host, nil)
	if err != nil {
		return nil, err
	}

	resp, err := v.client.Do(req)
	if err != nil {
		req, _ = http.NewRequestWithContext(ctx, "GET", "https://"+analysis.Host, nil)
		resp, err = v.client.Do(req)
		if err != nil {
			return nil, err
		}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	bodyStr := string(bodyBytes)

	if resp.StatusCode == 404 && (strings.Contains(bodyStr, "Sorry, this shop is currently unavailable.") || strings.Contains(bodyStr, "Only one step left!")) {
		return &core.VerificationResult{
			Provider:   v.Name(),
			Verified:   true,
			Confidence: 100,
			Evidence:   "A Shopify retornou uma assinatura de loja ausente; a possibilidade de vinculação não foi comprovada.",
		}, nil
	}

	return nil, nil
}
