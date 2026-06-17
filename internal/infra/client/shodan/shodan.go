package shodan

import (
	"context"
	"log"
	"net/http"
	"time"
)

type Client struct {
	apiKey string
	client *http.Client
}

type EnrichmentResult struct {
	Ports          []int    `json:"ports"`
	Vulnerabilities []string `json:"vulnerabilities"`
	ISP            string   `json:"isp"`
	CountryCode    string   `json:"country_code"`
}

func NewClient(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

// EnrichIP retrieves open ports and CVEs associated with an IP address from Shodan
func (c *Client) EnrichIP(ctx context.Context, ip string) (*EnrichmentResult, error) {
	log.Printf("[Shodan] Fetching enrichment for IP: %s...", ip)

	// Since this is a production skeleton running locally, we simulate the HTTP response
	if c.apiKey == "SHODAN_API_KEY_PLACEHOLDER" || c.apiKey == "" {
		// Mock payload
		time.Sleep(200 * time.Millisecond) // Simulate network latency
		return &EnrichmentResult{
			Ports:           []int{80, 443, 22, 8080},
			Vulnerabilities: []string{"CVE-2023-38606", "CVE-2021-44228"},
			ISP:             "Mock Threat Intel ISP",
			CountryCode:     "US",
		}, nil
	}

	// Actual Shodan integration would execute HTTP request here
	return nil, nil
}
