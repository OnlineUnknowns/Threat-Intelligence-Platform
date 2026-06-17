package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/threat-intel-platform/internal/domain/ioc"
	"github.com/threat-intel-platform/internal/infra/client/shodan"
	"github.com/threat-intel-platform/internal/infra/client/virustotal"
	"github.com/threat-intel-platform/internal/infra/client/whois"
	"github.com/threat-intel-platform/internal/infra/config"
	"github.com/threat-intel-platform/internal/infra/db/postgres"
	"github.com/threat-intel-platform/internal/infra/queue/rabbitmq"
)

func main() {
	log.Println("Starting Threat Intelligence Platform Enrichment Worker Service...")

	// 1. Load configuration
	cfg, err := config.LoadConfig("configs/config.yaml")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// 2. Initialize DB Repository and Broker Queue
	repo := postgres.NewPostgresRepository(
		cfg.DB.Postgres.Host,
		cfg.DB.Postgres.Port,
		cfg.DB.Postgres.User,
		cfg.DB.Postgres.Password,
		cfg.DB.Postgres.DBName,
		cfg.DB.Postgres.SSLMode,
	)

	broker := rabbitmq.NewBroker(cfg.RabbitMQ.URL)

	// 3. Initialize Enrichment Clients
	shodanClient := shodan.NewClient(cfg.Enrichment.Shodan.APIKey)
	vtClient := virustotal.NewClient(cfg.Enrichment.VirusTotal.APIKey)
	whoisClient := whois.NewClient()

	// 4. Define Enrichment Subscriber Handler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	enrichmentHandler := func(iocID string) error {
		// Fetch target IOC from Database
		indicator, err := repo.GetByID(ctx, iocID)
		if err != nil {
			return fmt.Errorf("failed to retrieve indicator: %v", err)
		}

		log.Printf("[Worker] Starting enrichment workflow for indicator: %s (Type: %s)", indicator.Value, indicator.Type)

		enrichedNotes := indicator.Description

		// Run Shodan enrichment for IPs
		if indicator.Type == ioc.TypeIPv4 || indicator.Type == ioc.TypeIPv6 {
			res, err := shodanClient.EnrichIP(ctx, indicator.Value)
			if err == nil {
				enrichedNotes += fmt.Sprintf(" | [Shodan] ISP: %s, Open Ports: %v, Vulns: %v", res.ISP, res.Ports, res.Vulnerabilities)
				// Adjust confidence score if Shodan confirms vulnerabilities
				if len(res.Vulnerabilities) > 0 {
					newScore, err := ioc.NewConfidenceScore(indicator.Confidence.Int() + 15)
					if err == nil {
						indicator.Confidence = newScore
					}
				}
			}
		}

		// Run WHOIS lookup for Domains
		if indicator.Type == ioc.TypeDomain {
			res, err := whoisClient.EnrichDomain(ctx, indicator.Value)
			if err == nil {
				enrichedNotes += fmt.Sprintf(" | [WHOIS] Registrar: %s, Registered: %s", res.Registrar, res.CreatedDate.Format("2006-01-02"))
			}
		}

		// Run VirusTotal lookup for all indicators
		vtRes, err := vtClient.EnrichIndicator(ctx, indicator.Value)
		if err == nil {
			enrichedNotes += fmt.Sprintf(" | [VirusTotal] Reputation: %d, Category: %s", vtRes.Reputation, vtRes.Category)
			// Boost confidence if VT votes confirm malicious nature
			if vtRes.MaliciousVotes > 10 {
				newScore, err := ioc.NewConfidenceScore(95)
				if err == nil {
					indicator.Confidence = newScore
				}
				indicator.Tags = append(indicator.Tags, "malicious")
			}
		}

		// Update database indicator record
		indicator.Description = enrichedNotes
		if err := repo.Update(ctx, indicator); err != nil {
			return fmt.Errorf("failed to save enriched indicator: %v", err)
		}

		log.Printf("[Worker] Enrichment successfully completed for: %s", indicator.Value)
		return nil
	}

	// 5. Start subscribing
	if err := broker.SubscribeEnrichmentTasks(ctx, enrichmentHandler); err != nil {
		log.Fatalf("Queue subscription failed: %v", err)
	}

	// 6. Graceful Shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down Enrichment Worker service gracefully...")
	cancel()

	log.Println("Enrichment Worker service stopped.")
}
