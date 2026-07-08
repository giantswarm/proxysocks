package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/giantswarm/proxysocks/internal/server"
)

var (
	socksAddr   string
	metricsAddr string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:           "proxysocks",
	Short:         "A SOCKS5 proxy server with optional htpasswd authentication",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		srv, err := server.New()
		if err != nil {
			return err
		}

		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		go func() {
			<-ctx.Done()
			// Restore default signal handling so a second signal
			// terminates immediately instead of waiting for the drain.
			stop()
		}()

		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		http.Handle("/metrics", promhttp.Handler())

		metricsServer := &http.Server{
			Addr:         metricsAddr,
			Handler:      nil,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  15 * time.Second,
		}
		metricsErr := make(chan error, 1)
		go func() {
			slog.Info("starting metrics server", "addr", metricsAddr)
			if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				metricsErr <- fmt.Errorf("metrics server: %w", err)
			}
			cancel()
		}()

		ln, err := net.Listen("tcp", socksAddr)
		if err != nil {
			return fmt.Errorf("listening on %s: %w", socksAddr, err)
		}

		slog.Info("starting SOCKS5 proxy server", "addr", socksAddr)
		serveErr := server.Serve(ctx, srv, ln)

		// Keep /metrics scrapeable during the drain; shut it down last.
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := metricsServer.Shutdown(shutdownCtx); err != nil {
			slog.Error("metrics server shutdown", "error", err)
		}

		select {
		case err := <-metricsErr:
			return err
		default:
		}
		return serveErr
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))

	err := rootCmd.Execute()
	if err != nil {
		slog.Error("command failed", "error", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringVar(&socksAddr, "socks-address", ":8000", "address the SOCKS5 proxy listens on")
	rootCmd.Flags().StringVar(&metricsAddr, "metrics-address", ":8090", "address the metrics server listens on")
}
