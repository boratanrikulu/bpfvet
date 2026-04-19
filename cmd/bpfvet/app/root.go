package app

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/boratanrikulu/bpfvet/pkg/analyzer"
	"github.com/boratanrikulu/bpfvet/pkg/report"
	"github.com/boratanrikulu/bpfvet/pkg/version"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "bpfvet <file.bpf.o> [file2.bpf.o ...]",
	Short: "BPF portability analyzer - reports minimum kernel version requirements",
	Args:  cobra.MinimumNArgs(1),
	RunE:  run,
	SilenceUsage: true,
}

func init() {
	rootCmd.Flags().BoolP("json", "j", false, "output in JSON format")
	rootCmd.Flags().BoolP("verbose", "v", false, "show detailed per-program analysis")
}

func run(cmd *cobra.Command, args []string) error {
	jsonOutput, _ := cmd.Flags().GetBool("json")
	verbose, _ := cmd.Flags().GetBool("verbose")

	type result struct {
		file   string
		report *report.Report
	}

	var results []result

	for _, filePath := range args {
		f, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("open %s: %w", filePath, err)
		}

		r, err := analyzer.Analyze(f)
		f.Close()
		if err != nil {
			return fmt.Errorf("analyze %s: %w", filePath, err)
		}

		results = append(results, result{file: filePath, report: r})
	}

	multi := len(results) > 1

	for i, res := range results {
		if multi {
			if i > 0 {
				fmt.Fprintln(os.Stdout)
			}
			fmt.Fprintf(os.Stdout, "==> %s <==\n\n", filepath.Base(res.file))
		}

		if jsonOutput {
			if err := report.WriteJSON(os.Stdout, res.report); err != nil {
				return err
			}
		} else {
			if err := report.WriteText(os.Stdout, res.report, verbose); err != nil {
				return err
			}
		}
	}

	if multi && !jsonOutput {
		fmt.Fprintln(os.Stdout)
		fmt.Fprintln(os.Stdout, "=============================")
		fmt.Fprintln(os.Stdout, "Summary")
		fmt.Fprintln(os.Stdout, "=============================")
		overallMax := version.V(0, 0)
		for _, res := range results {
			v := res.report.MinKernel
			fmt.Fprintf(os.Stdout, "  %-40s %s+\n", filepath.Base(res.file), v)
			if overallMax.Less(v) {
				overallMax = v
			}
		}
		fmt.Fprintf(os.Stdout, "\nMinimum kernel version (all files): %s\n", overallMax)
	}

	return nil
}

func Execute() error {
	return rootCmd.Execute()
}
