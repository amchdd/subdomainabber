package ratelimit

import (
	"context"
	"io"
	"net/http"
	"time"
)

type Waiter interface {
	Wait(context.Context) error
}

// Transport é um http.RoundTripper que aplica limitação de taxa a todas as
// requisições.
type Transport struct {
	Limiter Waiter
	Base    http.RoundTripper
	Timeout time.Duration
}

// RoundTrip executa uma única transação HTTP e aplica primeiro o limite de taxa.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Limiter != nil {
		if err := t.Limiter.Wait(req.Context()); err != nil {
			return nil, err
		}
	}

	activeRequest := req
	var cancel context.CancelFunc
	if t.Timeout > 0 {
		requestContext, requestCancel := context.WithTimeout(req.Context(), t.Timeout)
		cancel = requestCancel
		activeRequest = req.Clone(requestContext)
	}

	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	response, err := base.RoundTrip(activeRequest)
	if err != nil {
		if cancel != nil {
			cancel()
		}
		return nil, err
	}
	if cancel != nil {
		if response.Body == nil {
			cancel()
		} else {
			response.Body = &cancelOnCloseBody{ReadCloser: response.Body, cancel: cancel}
		}
	}
	return response, nil
}

// NewTransport cria um novo transporte HTTP com limitação de taxa.
func NewTransport(limiter Waiter, base http.RoundTripper) *Transport {
	return &Transport{
		Limiter: limiter,
		Base:    base,
	}
}

// NewTimedTransport aguarda o limitador global antes de iniciar o tempo limite
// de rede. Isso evita que o período na fila do limitador consuma o orçamento
// efetivo de E/S da requisição.
func NewTimedTransport(limiter Waiter, base http.RoundTripper, timeout time.Duration) *Transport {
	return &Transport{
		Limiter: limiter,
		Base:    base,
		Timeout: timeout,
	}
}

type cancelOnCloseBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (body *cancelOnCloseBody) Close() error {
	err := body.ReadCloser.Close()
	body.cancel()
	return err
}
