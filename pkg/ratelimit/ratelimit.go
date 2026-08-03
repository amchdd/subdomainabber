// Package ratelimit fornece um limitador de taxa baseado em balde de tokens
// para controlar requisições DNS/HTTP por segundo. É uma abstração fina sobre
// golang.org/x/time/rate com suporte ao modo sem limitação.
package ratelimit

import (
	"context"
	"sync/atomic"

	"golang.org/x/time/rate"
)

// Limiter controla a taxa de requisições por segundo usando um balde de tokens.
// Se o RPS for 0, o limitador não impõe limite.
type Limiter struct {
	limiter  *rate.Limiter
	disabled bool
	granted  atomic.Uint64
	waiting  atomic.Int64
}

// StatsSnapshot é um retrato pontual da atividade do limitador, livre de
// condições de corrida.
type StatsSnapshot struct {
	Granted uint64
	Waiting int64
}

// New cria um Limiter. Se rps == 0, retorna um limitador desabilitado.
// A capacidade de rajada é configurada como max(1, rps/10) para permitir pequenas rajadas
// sem sobrecarregar o alvo.
func New(rps int) *Limiter {
	if rps <= 0 {
		return &Limiter{disabled: true}
	}

	burst := rps / 10
	if burst < 1 {
		burst = 1
	}

	return &Limiter{
		limiter:  rate.NewLimiter(rate.Limit(rps), burst),
		disabled: false,
	}
}

// Wait bloqueia até que um token esteja disponível ou o contexto seja cancelado.
// Se o limitador estiver desabilitado (rps=0), retorna imediatamente sem erro.
func (l *Limiter) Wait(ctx context.Context) error {
	if l.disabled {
		l.granted.Add(1)
		return nil
	}

	l.waiting.Add(1)
	err := l.limiter.Wait(ctx)
	l.waiting.Add(-1)
	if err != nil {
		return err
	}
	l.granted.Add(1)
	return nil
}

// Enabled informa se a limitação de taxa está ativa.
func (l *Limiter) Enabled() bool {
	return !l.disabled
}

// Stats retorna os contadores do limitador sem bloquear requisições ativas.
func (l *Limiter) Stats() StatsSnapshot {
	if l == nil {
		return StatsSnapshot{}
	}
	return StatsSnapshot{
		Granted: l.granted.Load(),
		Waiting: l.waiting.Load(),
	}
}
