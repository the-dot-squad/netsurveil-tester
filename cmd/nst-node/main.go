// Command nst-node runs a NetSurveil tester node.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/the-dot-squad/netsurveil-tester/internal/api"
	"github.com/the-dot-squad/netsurveil-tester/internal/check"
	"github.com/the-dot-squad/netsurveil-tester/internal/config"
	"github.com/the-dot-squad/netsurveil-tester/internal/jobs"
	"github.com/the-dot-squad/netsurveil-tester/internal/netguard"
	"github.com/the-dot-squad/netsurveil-tester/internal/node"
)

var (
	version  = "dev"
	buildSig = "dev"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	healthcheck := flag.Bool("healthcheck", false, "probe the loopback health endpoint and exit (for container HEALTHCHECK)")
	flag.Parse()
	if *showVersion {
		fmt.Printf("nst-node %s (%s)\n", version, buildSig)
		return
	}
	if *healthcheck {
		os.Exit(runHealthcheck())
	}
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.LoadNode(os.Getenv)
	if err != nil {
		return err
	}
	log := newLogger(cfg.LogLevel)
	codec, err := api.NewCodec(cfg.Secret, cfg.ID)
	if err != nil {
		return err
	}
	guard := netguard.New(cfg.AllowPrivate)
	runner := check.NewRunner(check.Env{Guard: guard, NodeID: cfg.ID, Version: version}, log)
	store := jobs.New(runner.Run, jobs.DefaultLimits)
	defer store.Close()
	svc := node.New(codec, runner, store, version, log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Info("starting", "node", cfg.ID, "version", version, "build", buildSig,
		"inbound", cfg.ListenAddr != "", "feeds", len(cfg.FeedURLs), "allow_private", cfg.AllowPrivate)

	errc := make(chan error, 2)
	var servers []*http.Server
	serve := func(srv *http.Server) {
		servers = append(servers, srv)
		go func() {
			if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
	}
	// Request contexts end with ctx, so a submit waiting on its job returns at shutdown.
	baseCtx := func(net.Listener) context.Context { return ctx }
	if cfg.ListenAddr != "" {
		serve(&http.Server{
			Addr:              cfg.ListenAddr,
			Handler:           svc.Handler(cfg.PathPrefix, cfg.RateLimitPerMin),
			BaseContext:       baseCtx,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      node.MaxInboundWait + 15*time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    32 << 10,
			ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
		})
		log.Info("inbound listening", "addr", cfg.ListenAddr)
	}
	if cfg.HealthAddr != "" {
		serve(&http.Server{
			Addr:              cfg.HealthAddr,
			Handler:           svc.HealthHandler(),
			BaseContext:       baseCtx,
			ReadHeaderTimeout: 5 * time.Second,
			ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
		})
	}
	var pulling sync.WaitGroup
	if len(cfg.FeedURLs) > 0 {
		client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, MaxIdleConns: 4, IdleConnTimeout: 90 * time.Second}}
		pulling.Go(func() { svc.Pull(ctx, cfg.FeedURLs, client) })
	}

	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	stop()
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(sctx)
	}
	// Pull returns once its in-flight requests have delivered their final answers.
	pulling.Wait()
	return err
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(strings.ToUpper(level))); err != nil {
		l = slog.LevelInfo
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
	slog.SetDefault(log)
	return log
}

func runHealthcheck() int {
	cfg, err := config.LoadNode(os.Getenv)
	if err != nil {
		return 1
	}
	if cfg.HealthAddr == "" {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+cfg.HealthAddr+"/healthz", nil)
	if err != nil {
		return 1
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
