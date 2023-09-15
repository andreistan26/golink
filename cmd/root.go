package cmd

import (
	"context"
	"runtime/pprof"

	"os"

	"github.com/andreistan26/golink/pkg/linker"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slog"
)

func Execute(ctx context.Context) error {
	return nil
}

func RootCmd() *cobra.Command {
	opts := struct {
		Profile bool
		Debug   bool
	}{
		false,
		false,
	}

	rootCmd := &cobra.Command{
		Use:   "golink",
		Short: "Golink is an ELF linker for x86-64",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if opts.Debug {
				slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
					AddSource: false,
					Level:     slog.LevelDebug,
				})))
			}

			if opts.Profile {
				file, err := os.Create("cpu.pprof")
				if err != nil {
					return err
				}

				pprof.StartCPUProfile(file)
			}
			return nil
		},
		PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
			if opts.Profile {
				pprof.StopCPUProfile()
			}
			return nil
		},
	}

	rootCmd.PersistentFlags().BoolVarP(&opts.Profile, "profile", "p", false, "enable profiling")
	rootCmd.PersistentFlags().BoolVarP(&opts.Debug, "debug", "d", false, "enable debugging")

	rootCmd.AddCommand(linkerCmd())

	return rootCmd
}

func linkerCmd() *cobra.Command {
	linkerCmd := &cobra.Command{
		Use:   "link",
		Short: "Link input files",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			linker.Link(linker.LinkerInputs{Filenames: args[:]})
			return nil
		},
	}

	return linkerCmd
}
