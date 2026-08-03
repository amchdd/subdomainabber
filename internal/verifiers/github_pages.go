package verifiers

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
)

type GitHubPagesVerifier struct {
	client *http.Client
}

func NewGitHubPagesVerifier(cfg Config) *GitHubPagesVerifier {
	return &GitHubPagesVerifier{client: cfg.Client}
}

func (v *GitHubPagesVerifier) Name() string {
	return "GitHub Pages"
}

func (v *GitHubPagesVerifier) Verify(ctx context.Context, analysis *core.HostAnalysis) (*core.VerificationResult, error) {
	// Exige um CNAME compatível com o GitHub Pages.
	if !hasProviderCNAME(analysis, "github.io") {
		return nil, nil
	}

	// Confirma a resposta específica por uma requisição HTTP ativa.
	client := v.client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+analysis.Host, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		// Repete a verificação por HTTPS.
		req, _ = http.NewRequestWithContext(ctx, "GET", "https://"+analysis.Host, nil)
		resp, err = client.Do(req)
		if err != nil {
			return nil, err
		}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	bodyStr := string(body)

	// A resposta 404 com a mensagem específica confirma a assinatura do provedor.
	if resp.StatusCode == 404 && strings.Contains(bodyStr, "There isn't a GitHub Pages site here.") {
		return &core.VerificationResult{
			Provider:   v.Name(),
			Verified:   true,
			Confidence: 100,
			Evidence:   "Domínio responde com 404 nativo do GitHub Pages indicando ausência de repositório vinculado.",
		}, nil
	}

	return nil, nil
}
