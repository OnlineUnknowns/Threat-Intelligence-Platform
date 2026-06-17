package whois

import (
	"context"
	"log"
	"time"
)

type Client struct{}

type EnrichmentResult struct {
	Registrar  string    `json:"registrar"`
	Country    string    `json:"country"`
	CreatedDate time.Time `json:"created_date"`
	ExpiryDate  time.Time `json:"expiry_date"`
}

func NewClient() *Client {
	return &Client{}
}

// EnrichDomain retrieves registration context for a given domain name
func (c *Client) EnrichDomain(ctx context.Context, domain string) (*EnrichmentResult, error) {
	log.Printf("[WHOIS] Querying registrar lookup for domain: %s...", domain)

	// Simulate socket WHOIS protocol connection
	time.Sleep(150 * time.Millisecond)

	return &EnrichmentResult{
		Registrar:   "NameCheap Inc.",
		Country:     "IS", // Iceland (Privacy protection proxy)
		CreatedDate: time.Now().AddDate(-3, 0, 0),
		ExpiryDate:  time.Now().AddDate(1, 0, 0),
	}, nil
}
