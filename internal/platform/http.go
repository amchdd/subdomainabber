package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

const maxResponseSize = 16 << 20
const maxAttempts = 4

type apiClient struct {
	http *http.Client
	base *url.URL
	auth func(*http.Request)
	wait func(context.Context) error
}

func newAPIClient(client *http.Client, base string, auth func(*http.Request)) *apiClient {
	if client == nil {
		client = http.DefaultClient
	}
	parsed, _ := url.Parse(strings.TrimRight(base, "/"))
	return &apiClient{http: client, base: parsed, auth: auth}
}

func (client *apiClient) get(ctx context.Context, path string, output any) error {
	endpoint, err := client.endpoint(path)
	if err != nil {
		return err
	}
	var lastError error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if client.wait != nil {
			if err := client.wait(ctx); err != nil {
				return err
			}
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		if err != nil {
			return err
		}
		if client.auth != nil {
			client.auth(request)
		}
		response, err := client.http.Do(request)
		if err != nil {
			lastError = fmt.Errorf("consultando %s: %w", endpoint.Path, err)
			if attempt+1 == maxAttempts {
				return lastError
			}
			if err := waitRetry(ctx, retryDelay("", attempt)); err != nil {
				return err
			}
			continue
		}
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			decoder := json.NewDecoder(io.LimitReader(response.Body, maxResponseSize))
			decoder.UseNumber()
			err := decoder.Decode(output)
			response.Body.Close()
			if err != nil {
				return fmt.Errorf("decodificando %s: %w", endpoint.Path, err)
			}
			return nil
		}
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		response.Body.Close()
		lastError = fmt.Errorf("%s retornou HTTP %d: %s", endpoint.Path, response.StatusCode, strings.TrimSpace(string(body)))
		if !retryable(response.StatusCode) || attempt+1 == maxAttempts {
			return lastError
		}
		if err := waitRetry(ctx, retryDelay(response.Header.Get("Retry-After"), attempt)); err != nil {
			return err
		}
	}
	return lastError
}

func apiPacer(base, host string, requestsPerMinute int) func(context.Context) error {
	parsed, err := url.Parse(base)
	if err != nil || !strings.EqualFold(parsed.Hostname(), host) || requestsPerMinute <= 0 {
		return nil
	}
	limiter := rate.NewLimiter(rate.Every(time.Minute/time.Duration(requestsPerMinute)), 1)
	return limiter.Wait
}

func retryable(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusBadGateway ||
		status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
}

func retryDelay(value string, attempt int) time.Duration {
	if seconds, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && seconds >= 0 {
		return capDelay(time.Duration(seconds) * time.Second)
	}
	if date, err := http.ParseTime(value); err == nil {
		return capDelay(time.Until(date))
	}
	return capDelay(time.Second << attempt)
}

func capDelay(delay time.Duration) time.Duration {
	if delay < 0 {
		return 0
	}
	if delay > 30*time.Second {
		return 30 * time.Second
	}
	return delay
}

func waitRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (client *apiClient) endpoint(path string) (*url.URL, error) {
	if client.base == nil {
		return nil, fmt.Errorf("URL base da plataforma inválida")
	}
	reference, err := url.Parse(path)
	if err != nil {
		return nil, err
	}
	basePath := strings.TrimRight(client.base.Path, "/")
	if !reference.IsAbs() && strings.HasPrefix(path, "/") && basePath != "" &&
		reference.Path != basePath && !strings.HasPrefix(reference.Path, basePath+"/") {
		reference.Path = basePath + "/" + strings.TrimLeft(reference.Path, "/")
	}
	endpoint := client.base.ResolveReference(reference)
	if !strings.EqualFold(endpoint.Scheme, client.base.Scheme) || !strings.EqualFold(endpoint.Host, client.base.Host) {
		return nil, fmt.Errorf("paginação apontou para uma origem diferente")
	}
	return endpoint, nil
}

func visitPage(seen map[string]struct{}, path string) error {
	if _, found := seen[path]; found {
		return fmt.Errorf("paginação repetiu a página %s", path)
	}
	seen[path] = struct{}{}
	return nil
}

type pageLinks struct {
	Next string `json:"next"`
}
