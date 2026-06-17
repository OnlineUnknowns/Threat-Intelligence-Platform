package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/threat-intel-platform/internal/app/ingest"
	"github.com/threat-intel-platform/internal/infra/config"
	"github.com/threat-intel-platform/internal/infra/db/postgres"
	"github.com/threat-intel-platform/internal/infra/queue/rabbitmq"
)

func main() {
	log.Println("Starting Threat Intelligence Platform Ingestion Daemon...")

	// 1. Load configuration
	cfg, err := config.LoadConfig("configs/config.yaml")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// 2. Initialize database and broker
	repo := postgres.NewPostgresRepository(
		cfg.DB.Postgres.Host,
		cfg.DB.Postgres.Port,
		cfg.DB.Postgres.User,
		cfg.DB.Postgres.Password,
		cfg.DB.Postgres.DBName,
		cfg.DB.Postgres.SSLMode,
	)

	broker := rabbitmq.NewBroker(cfg.RabbitMQ.URL)
	ingestService := ingest.NewIngestService(repo, broker)

	// 3. Setup ingestion cron loop
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	stopChan := make(chan struct{})
	go func() {
		// Run initial ingest at startup for demo
		ctx := context.Background()
		log.Println("[IngestDaemon] Triggering startup ingestion scan...")
		_ = ingestService.IngestFromRSS(ctx, ingest.SampleRSSFeed())
		_ = ingestService.IngestFromSTIX(ctx, ingest.SampleSTIXBundle())

		for {
			select {
			case <-ticker.C:
				log.Println("[IngestDaemon] Running scheduled cron ingestion cycle...")
				_ = ingestService.IngestFromRSS(ctx, ingest.SampleRSSFeed())
				_ = ingestService.IngestFromSTIX(ctx, ingest.SampleSTIXBundle())
			case <-stopChan:
				return
			}
		}
	}()

	// 4. Graceful Shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down Ingestion daemon gracefully...")
	close(stopChan)

	log.Println("Ingestion daemon stopped.")
}
