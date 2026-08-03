package cmd

import (
	"fmt"

	"github.com/amchdd/subdomainabber/internal/benchmark"
	"github.com/spf13/cobra"
)

var benchmarkCmd = &cobra.Command{
	Use:   "benchmark",
	Short: "Executa a suíte de benchmark da classificação",
}

var syntheticCmd = &cobra.Command{
	Use:   "synthetic",
	Short: "Executa a L1 — simulação DNS/HTTP para validar a classificação principal",
	RunE: func(cmd *cobra.Command, args []string) error {
		if !benchmark.RunL1Synthetic() {
			return fmt.Errorf("benchmark sintético encontrou regressões")
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(benchmarkCmd)
	benchmarkCmd.AddCommand(syntheticCmd)
	benchmarkCmd.AddCommand(&cobra.Command{
		Use:   "mutator",
		Short: "Mede o HTTP Mutator em cenários locais controlados de borda e servidor de origem",
		RunE: func(cmd *cobra.Command, args []string) error {
			metrics := benchmark.RunMutatorBenchmark()
			benchmark.PrintMutatorBenchmark(metrics)
			if metrics.FalsePositives > 0 {
				return fmt.Errorf("benchmark do Mutator encontrou falsos positivos")
			}
			if metrics.FalseNegatives > 0 {
				return fmt.Errorf("benchmark do Mutator encontrou falsos negativos")
			}
			return nil
		},
	})

	var cmdGold = &cobra.Command{
		Use:   "gold [dataset-dir]",
		Short: "Executa testes reais L2 contra hosts na internet usando o conjunto de dados ouro",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := benchmark.RunL2Gold(cmd.Context(), args[0]); err != nil {
				return fmt.Errorf("benchmark com o conjunto de dados ouro falhou: %w", err)
			}
			return nil
		},
	}

	var cmdRegression = &cobra.Command{
		Use:   "regression [dataset-dir]",
		Short: "Executa testes L3 isolados configurados via JSON",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !benchmark.RunL3Regression(args[0]) {
				return fmt.Errorf("benchmark de regressão encontrou falhas")
			}
			return nil
		},
	}

	benchmarkCmd.AddCommand(cmdGold, cmdRegression)
}
