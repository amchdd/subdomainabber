package notify

import (
	"context"
	"errors"
	"fmt"
)

// notificationTransportError evita que erros de transporte exponham URLs com
// credenciais. Os valores originais não são incorporados à mensagem retornada.
func notificationTransportError(service string, err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("envio da notificação ao %s cancelado: %w", service, context.Canceled)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("tempo limite excedido ao enviar a notificação ao %s: %w", service, context.DeadlineExceeded)
	default:
		return fmt.Errorf("falha de transporte ao enviar a notificação ao %s", service)
	}
}
