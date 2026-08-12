package cmd

import (
	"fmt"

	"github.com/amchdd/subdomainabber/internal/export"
	"github.com/spf13/cobra"
)

var (
	bundleOut        string
	bundlePrivateKey string
	privateKeyOut    string
	publicKeyOut     string
	bundlePublicKey  string
)

var bundleCmd = &cobra.Command{
	Use:   "bundle <execução>",
	Short: "Gera um bundle forense assinado com Ed25519",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) (runErr error) {
		if bundleOut == "" || bundlePrivateKey == "" {
			return fmt.Errorf("informe --out e --signing-key")
		}
		store, err := openStore()
		if err != nil {
			return err
		}
		defer closeStoreWithError(store, &runErr)
		analyses, err := store.Observations(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		if len(analyses) == 0 {
			return fmt.Errorf("a execução %s não possui observações", args[0])
		}
		if err := export.WriteBundle(bundleOut, args[0], bundlePrivateKey, analyses); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Bundle assinado gravado em %s\n", bundleOut)
		return nil
	},
}

var bundleKeyCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Gera um par de chaves Ed25519 para bundles",
	RunE: func(cmd *cobra.Command, args []string) error {
		if privateKeyOut == "" || publicKeyOut == "" {
			return fmt.Errorf("informe --private-out e --public-out")
		}
		if err := export.GenerateKey(privateKeyOut, publicKeyOut); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Par de chaves Ed25519 criado")
		return nil
	},
}

var bundleVerifyCmd = &cobra.Command{
	Use:   "verify-bundle <arquivo>",
	Short: "Verifica o digest e a assinatura de um bundle",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if bundlePublicKey == "" {
			return fmt.Errorf("informe --public-key para validar a autoria")
		}
		if err := export.VerifyBundle(args[0], bundlePublicKey); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Bundle íntegro e assinatura válida")
		return nil
	},
}

func init() {
	dbCmd.AddCommand(bundleCmd, bundleKeyCmd, bundleVerifyCmd)
	bundleCmd.Flags().StringVarP(&bundleOut, "out", "o", "", "Arquivo JSON de saída")
	bundleCmd.Flags().StringVar(&bundlePrivateKey, "signing-key", "", "Arquivo da chave privada Ed25519")
	bundleKeyCmd.Flags().StringVar(&privateKeyOut, "private-out", "", "Arquivo novo para a chave privada")
	bundleKeyCmd.Flags().StringVar(&publicKeyOut, "public-out", "", "Arquivo novo para a chave pública")
	bundleVerifyCmd.Flags().StringVar(&bundlePublicKey, "public-key", "", "Chave pública Ed25519 confiável")
}
