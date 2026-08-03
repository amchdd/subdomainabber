package passive

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

type WaybackCDXProvider struct {
	Client         *http.Client
	BaseURL        string // Usado nos testes da pesquisa CDX.
	ArchiveBaseURL string // Usado nos testes dos retratos arquivados.
}

func (p *WaybackCDXProvider) Name() string {
	return "WaybackCDX"
}

func (p *WaybackCDXProvider) Enumerate(ctx context.Context, domain string, out chan<- string) error {
	client := passiveHTTPClient(p.Client)

	resumeKey := ""
	seenResumeKeys := make(map[string]struct{})
	snapshots := 0
	snapshotFailures := 0
	var firstSnapshotFailure error

	normalizedDomain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if normalizedDomain == "" {
		return fmt.Errorf("o domínio da consulta CDX está vazio")
	}
	label := `[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?`
	subdomainPattern := regexp.MustCompile(`(?i)(?:` + label + `\.)+` + regexp.QuoteMeta(normalizedDomain) + `\.?`)

	baseURL := p.BaseURL
	if baseURL == "" {
		baseURL = "https://web.archive.org/cdx/search/cdx"
	}

	for page := 0; page < maxWaybackCDXPages; page++ {
		query := url.Values{}
		query.Set("url", normalizedDomain)
		query.Set("matchType", "domain")
		query.Set("filter", "mimetype:application/javascript")
		query.Set("fl", "original,timestamp")
		query.Set("collapse", "urlkey")
		query.Set("showResumeKey", "true")
		if resumeKey != "" {
			query.Set("resumeKey", resumeKey)
		}
		separator := "?"
		if strings.Contains(baseURL, "?") {
			separator = "&"
		}
		request, err := newGETRequest(ctx, baseURL+separator+query.Encode(), "índice CDX da Wayback Machine")
		if err != nil {
			return err
		}
		indexBody, err := fetchLimited(client, request, "índice CDX da Wayback Machine", maxCDXIndexResponseBytes)
		if err != nil {
			return err
		}

		scanner := bufio.NewScanner(bytes.NewReader(indexBody))
		scanner.Buffer(make([]byte, 64<<10), 1<<20)
		foundResumeKey := ""
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())

			if line == "" {
				if scanner.Scan() {
					foundResumeKey = strings.TrimSpace(scanner.Text())
				}
				break
			}

			parts := strings.Fields(line)
			if len(parts) < 2 {
				continue
			}

			if snapshots >= maxWaybackSnapshots {
				return fmt.Errorf("a consulta CDX atingiu o limite de %d retratos", maxWaybackSnapshots)
			}
			snapshots++

			originalURL := parts[0]
			timestamp := parts[1]
			archiveBase := p.ArchiveBaseURL
			if archiveBase == "" {
				archiveBase = "https://web.archive.org"
			}
			snapshotURL := fmt.Sprintf("%s/web/%sif_/%s", strings.TrimSuffix(archiveBase, "/"), timestamp, originalURL)
			snapshotRequest, err := newGETRequest(ctx, snapshotURL, "retrato da Wayback Machine")
			if err != nil {
				return err
			}
			snapshotBody, err := fetchLimited(client, snapshotRequest, "retrato da Wayback Machine", maxWaybackSnapshotBytes)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				snapshotFailures++
				if firstSnapshotFailure == nil {
					firstSnapshotFailure = err
				}
				continue
			}

			for _, match := range subdomainPattern.FindAllString(string(snapshotBody), -1) {
				match = strings.TrimSuffix(strings.ToLower(match), ".")
				if err := emit(ctx, out, match); err != nil {
					return err
				}
			}
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("lendo resposta do índice CDX: %w", err)
		}

		if foundResumeKey != "" {
			if _, repeated := seenResumeKeys[foundResumeKey]; repeated {
				return fmt.Errorf("o índice CDX repetiu a chave de retomada %q", foundResumeKey)
			}
			seenResumeKeys[foundResumeKey] = struct{}{}
			resumeKey = foundResumeKey
		} else {
			if firstSnapshotFailure != nil {
				return fmt.Errorf(
					"%d retrato(s) da Wayback Machine não puderam ser processados; primeiro erro: %w",
					snapshotFailures,
					firstSnapshotFailure,
				)
			}
			return nil
		}
	}

	return fmt.Errorf("a consulta CDX atingiu o limite de %d páginas", maxWaybackCDXPages)
}
