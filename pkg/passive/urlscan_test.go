package passive

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestURLScanRejectsRepeatedPaginationCursor(t *testing.T) {
	var requests atomic.Int64
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		response, _ := responseWithBody(
			http.StatusOK,
			`{"results":[{"page":{"domain":"api.example.com"},"sort":["cursor"]}],"has_more":true}`,
		)
		return response, nil
	})}
	provider := &URLScanProvider{Client: client}

	err := provider.Enumerate(context.Background(), "example.com", make(chan string, 4))
	if err == nil || !strings.Contains(err.Error(), "repetiu o cursor de paginação") {
		t.Fatalf("o cursor repetido não foi rejeitado: %v", err)
	}
	if requests.Load() != 2 {
		t.Fatalf("quantidade inesperada de páginas consultadas: %d", requests.Load())
	}
}

func TestURLScanEncodesDomainAndCursor(t *testing.T) {
	var secondQuery string
	var requests atomic.Int64
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		current := requests.Add(1)
		if current == 2 {
			secondQuery = request.URL.RawQuery
			response, _ := responseWithBody(http.StatusOK, `{"results":[],"has_more":false}`)
			return response, nil
		}
		response, _ := responseWithBody(
			http.StatusOK,
			`{"results":[{"page":{"domain":"api.example.com"},"sort":["um,dois","três quatro"]}],"has_more":true}`,
		)
		return response, nil
	})}
	provider := &URLScanProvider{Client: client}

	if err := provider.Enumerate(context.Background(), "example.com", make(chan string, 4)); err != nil {
		t.Fatalf("a paginação falhou: %v", err)
	}
	if !strings.Contains(secondQuery, "search_after=um%2Cdois%2Ctr%C3%AAs+quatro") {
		t.Fatalf("cursor sem codificação adequada: %q", secondQuery)
	}
}

func TestURLScanLimitsPagination(t *testing.T) {
	var requests atomic.Int64
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		current := requests.Add(1)
		response, _ := responseWithBody(
			http.StatusOK,
			fmt.Sprintf(`{"results":[{"page":{"domain":""},"sort":[%d]}],"has_more":true}`, current),
		)
		return response, nil
	})}
	provider := &URLScanProvider{Client: client}

	err := provider.Enumerate(context.Background(), "example.com", make(chan string, 1))
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("limite de %d páginas", maxURLScanPages)) {
		t.Fatalf("o limite de páginas não foi aplicado: %v", err)
	}
	if requests.Load() != int64(maxURLScanPages) {
		t.Fatalf("quantidade inesperada de páginas consultadas: %d", requests.Load())
	}
}
