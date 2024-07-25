package main

import (
	"SMTech/internal/app"
	"SMTech/internal/config"
	"context"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

const (
	envLocal = "local"
	envDev   = "dev"
	envProd  = "prod"
)

func main() {

	ctx := context.Background()

	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	var wg sync.WaitGroup

	cfg := config.MustLoad()

	log := setupLogger(cfg.Env)

	log.Info("starting app", slog.Any("cfg", cfg))

	application := app.New(log, cfg.GRPC.Port, cfg.StoragePath)

	wg.Add(1)

	go func() {

		defer wg.Done()

		application.GROCSrv.MustRun()

	}()

	<-ctx.Done()

	log.Info("stopping application", slog.String("signal", ctx.Err().Error()))

	application.GROCSrv.Stop()

	log.Info("application Stopped")

	wg.Wait()
}

func setupLogger(env string) *slog.Logger {
	var log *slog.Logger

	switch env {
	case envLocal:
		log = slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envDev:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envProd:
		log = slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	}

	return log
}
