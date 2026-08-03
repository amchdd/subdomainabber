package verifiers

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
)

type NetlifyVerifier struct {
	client *http.Client
}

func NewNetlifyVerifier(cfg Config) *NetlifyVerifier {
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &NetlifyVerifier{
		client: client,
	}
}

func (v *NetlifyVerifier) Name() string {
	return "Netlify"
}

func (v *NetlifyVerifier) Verify(ctx context.Context, analysis *core.HostAnalysis) (*core.VerificationResult, error) {
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

	if strings.Contains(bodyStr, "Not Found - Request ID:") || (resp.StatusCode == 404 && strings.Contains(strings.ToLower(resp.Header.Get("server")), "netlify")) {
		return &core.VerificationResult{
			Provider:   v.Name(),
			Verified:   true,
			Confidence: 95,
			Evidence:   "A Netlify retornou uma assinatura de site ausente; a possibilidade de reivindicação não foi comprovada.",
		}, nil
	}

	return nil, nil
}
