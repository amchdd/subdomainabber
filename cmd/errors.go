package cmd

import (
	"errors"
	"fmt"

	"github.com/amchdd/subdomainabber/internal/storage"
)

// closeStoreWithError preserva o erro principal do comando e também informa
// uma eventual falha ao encerrar a conexão com o banco de dados.
func closeStoreWithError(store *storage.Store, result *error) {
	if store == nil || result == nil {
		return
	}
	if err := store.Close(); err != nil {
		*result = errors.Join(*result, fmt.Errorf("erro ao fechar o banco de dados: %w", err))
	}
}
