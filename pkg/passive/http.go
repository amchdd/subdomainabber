package passive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	maxPassiveAPIResponseBytes int64 = 8 << 20
	maxCDXIndexResponseBytes   int64 = 8 << 20
	maxWaybackSnapshotBytes    int64 = 2 << 20

	// Estes limites evitam que uma única fonte monopolize o lote. Cada retrato
	// arquivado ainda pode ter até 2 MiB.
	maxWaybackCDXPages  = 10
	maxWaybackSnapshots = 100
	maxURLScanPages     = 20
)

// passiveHTTPClient preserva o transporte, o proxy, o limitador e o timeout do
// cliente compartilhado. A cópia acrescenta apenas uma proteção local contra
// redirecionamentos para outra origem. O fallback existe para consumidores da
// biblioteca que não usam o Engine e não depende do cliente HTTP global.
func passiveHTTPClient(shared *http.Client) *http.Client {
	if shared == nil {
		shared = &http.Client{Timeout: 15 * time.Second}
	}

	client := *shared
	configuredRedirectPolicy := shared.CheckRedirect
	client.CheckRedirect = func(request *http.Request, previous []*http.Request) error {
		if len(previous) >= 10 {
			return fmt.Errorf("interrompido após 10 redirecionamentos")
		}
		if len(previous) > 0 && !sameOrigin(request.URL, previous[0].URL) {
			return http.ErrUseLastResponse
		}
		if configuredRedirectPolicy != nil {
			return configuredRedirectPolicy(request, previous)
		}
		return nil
	}
	return &client
}

func sameOrigin(current, initial *url.URL) bool {
	if current == nil || initial == nil {
		return false
	}
	return strings.EqualFold(current.Scheme, initial.Scheme) &&
		strings.EqualFold(current.Host, initial.Host)
}

func newGETRequest(ctx context.Context, rawURL, source string) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("criando requisição para %s: %w", source, err)
	}
	return request, nil
}

func fetchLimited(client *http.Client, request *http.Request, source string, limit int64) ([]byte, error) {
	response, err := client.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, fmt.Errorf("consultando %s: %w", source, sanitizedTransportError(err))
	}
	if response == nil || response.Body == nil {
		return nil, fmt.Errorf("%s retornou uma resposta HTTP sem corpo", source)
	}

	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return nil, fmt.Errorf("%s retornou HTTP %d", source, response.StatusCode)
	}

	body, readErr := io.ReadAll(io.LimitReader(response.Body, limit+1))
	closeErr := response.Body.Close()
	if readErr != nil {
		return nil, fmt.Errorf("lendo resposta de %s: %w", source, readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("fechando resposta de %s: %w", source, closeErr)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("a resposta de %s excedeu o limite de %d bytes", source, limit)
	}
	return body, nil
}

func sanitizedTransportError(err error) error {
	for depth := 0; depth < 16; depth++ {
		var urlError *url.Error
		if !errors.As(err, &urlError) || urlError.Err == nil {
			return err
		}
		err = urlError.Err
	}
	return errors.New("falha de transporte HTTP")
}

func emit(ctx context.Context, out chan<- string, value string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case out <- value:
		return nil
	}
}
