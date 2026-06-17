package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/threat-intel-platform/internal/app/ingest"
	"github.com/threat-intel-platform/internal/infra/config"
	"github.com/threat-intel-platform/internal/infra/db/postgres"
	infraHttp "github.com/threat-intel-platform/internal/presentation/http"
	v1 "github.com/threat-intel-platform/internal/presentation/http/v1"
	"github.com/threat-intel-platform/internal/infra/queue/rabbitmq"
)

func main() {
	log.Println("Starting Threat Intelligence Platform API Service...")

	// 1. Load configuration
	cfg, err := config.LoadConfig("configs/config.yaml")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// 2. Initialize Database & Queue Broker with fallbacks
	repo := postgres.NewPostgresRepository(
		cfg.DB.Postgres.Host,
		cfg.DB.Postgres.Port,
		cfg.DB.Postgres.User,
		cfg.DB.Postgres.Password,
		cfg.DB.Postgres.DBName,
		cfg.DB.Postgres.SSLMode,
	)

	broker := rabbitmq.NewBroker(cfg.RabbitMQ.URL)

	// 3. Initialize Domain Services & HTTP API handlers
	ingestService := ingest.NewIngestService(repo, broker)
	handlers := v1.NewAPIHandlers(repo, ingestService, broker)
	router := infraHttp.SetupRouter(handlers)

	serverAddr := fmt.Sprintf(":%d", cfg.Server.Port)
	srv := &http.Server{
		Addr:    serverAddr,
		Handler: router,
	}

	// 4. Run HTTP server in a goroutine
	go func() {
		log.Printf("API Server listening on %s", serverAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Listen and Serve error: %v", err)
		}
	}()

	// 5. Graceful Shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down API server gracefully...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("API service stopped.")
}
