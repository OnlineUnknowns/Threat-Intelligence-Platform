package ingest

import (
	"context"
	"log"
	"strings"

	"github.com/threat-intel-platform/internal/domain/ioc"
	"github.com/threat-intel-platform/internal/infra/parser/rss"
	"github.com/threat-intel-platform/internal/infra/parser/stix"
	"github.com/threat-intel-platform/internal/infra/queue/rabbitmq"
)

type IngestService struct {
	repo   ioc.Repository
	broker rabbitmq.Broker
}

func NewIngestService(repo ioc.Repository, broker rabbitmq.Broker) *IngestService {
	return &IngestService{
		repo:   repo,
		broker: broker,
	}
}

// IngestFromRSS parses standard XML threat feeds and registers indicators
func (s *IngestService) IngestFromRSS(ctx context.Context, xmlFeed string) error {
	reader := strings.NewReader(xmlFeed)
	indicators, err := rss.ParseFeed(reader)
	if err != nil {
		return err
	}

	log.Printf("[Ingestion] Parsed %d indicators from RSS feed.", len(indicators))

	for _, item := range indicators {
		// Save to db
		if err := s.repo.Create(ctx, item); err != nil {
			log.Printf("[Ingestion] Skip duplicate or invalid RSS item: %v", err)
			continue
		}

		// Queue background enrichment
		_ = s.broker.PublishEnrichmentTask(ctx, item.ID)
	}

	return nil
}

// IngestFromSTIX parses STIX 2.1 bundles and indexes threat information
func (s *IngestService) IngestFromSTIX(ctx context.Context, jsonBundle string) error {
	reader := strings.NewReader(jsonBundle)
	stixObjects, err := stix.ParseBundle(reader)
	if err != nil {
		return err
	}

	log.Printf("[Ingestion] Parsed STIX bundle. Indicators: %d, Actors: %d, Relationships: %d",
		len(stixObjects.Indicators), len(stixObjects.ThreatActors), len(stixObjects.Relationships))

	for _, item := range stixObjects.Indicators {
		if err := s.repo.Create(ctx, item); err != nil {
			log.Printf("[Ingestion] Skip duplicate or invalid STIX indicator: %v", err)
			continue
		}

		// Queue background enrichment
		_ = s.broker.PublishEnrichmentTask(ctx, item.ID)
	}

	// We can save campaigns, threat actors, and relationships in their respective repositories similarly.
	return nil
}

// SampleRSSFeed returns static mock XML data for local execution demo
func SampleRSSFeed() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>OSINT Threat Intelligence Feed</title>
    <item>
      <title>New Malware C2 Detected</title>
      <description>IP address 198.51.100.42 was observed serving payload with SHA256: d5a34e803d15ff1e204c3bd1788bc3b8b1db7b8e5c1a7d65377f0a65c404cf38</description>
      <pubDate>Wed, 17 Jun 2026 12:00:00 GMT</pubDate>
    </item>
    <item>
      <title>Suspicious Phishing Domain Registered</title>
      <description>Domain malicious-update-portal.com detected imitating corporate logins.</description>
      <pubDate>Wed, 17 Jun 2026 14:30:00 GMT</pubDate>
    </item>
  </channel>
</rss>`
}

// SampleSTIXBundle returns static mock JSON STIX 2.1 data for local execution demo
func SampleSTIXBundle() string {
	return `{
  "type": "bundle",
  "id": "bundle--5d48721c-a111-4775-a836-e0e64b859942",
  "spec_version": "2.1",
  "objects": [
    {
      "type": "indicator",
      "id": "indicator--8e2e2d2b-1a2f-45e0-81f1-a1e62688f8d9",
      "created": "2026-06-17T15:00:00.000Z",
      "modified": "2026-06-17T15:00:00.000Z",
      "name": "Malicious IP Indicator",
      "description": "IP associated with threat actor CozyBear scanning activity.",
      "pattern": "[ipv4-addr:value = '203.0.113.199']",
      "pattern_type": "stix",
      "labels": ["malicious-activity", "scanning"]
    },
    {
      "type": "threat-actor",
      "id": "threat-actor--df33fae9-1144-48cc-8d26-ccbdc0bc62e1",
      "created": "2026-06-17T15:00:00.000Z",
      "modified": "2026-06-17T15:00:00.000Z",
      "name": "CozyBear APT29",
      "description": "State-sponsored espionage group.",
      "threat_actor_types": ["nation-state"],
      "aliases": ["APT29", "CozyBear"],
      "goals": ["intelligence-collection"],
      "sophistication": "advanced"
    },
    {
      "type": "relationship",
      "id": "relationship--c66802f1-6789-411a-8ff4-93c6f6630f9a",
      "created": "2026-06-17T15:00:00.000Z",
      "modified": "2026-06-17T15:00:00.000Z",
      "relationship_type": "indicates",
      "source_ref": "indicator--8e2e2d2b-1a2f-45e0-81f1-a1e62688f8d9",
      "target_ref": "threat-actor--df33fae9-1144-48cc-8d26-ccbdc0bc62e1"
    }
  ]
}`
}
