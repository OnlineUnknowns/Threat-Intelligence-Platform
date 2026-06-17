package rss

import (
	"encoding/xml"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/threat-intel-platform/internal/domain/ioc"
)

var (
	ipRegex     = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	domainRegex = regexp.MustCompile(`\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b`)
	hash256Reg  = regexp.MustCompile(`\b[a-fA-F0-9]{64}\b`)
)

type RssFeed struct {
	XMLName xml.Name `xml:"rss"`
	Channel Channel  `xml:"channel"`
}

type Channel struct {
	Title string `xml:"title"`
	Items []Item `xml:"item"`
}

type Item struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	Description string `xml:"description"`
	PubDate     string `xml:"pubDate"`
}

// ParseFeed parses RSS XML from a stream and extracts indicators
func ParseFeed(r io.Reader) ([]*ioc.IOC, error) {
	var feed RssFeed
	dec := xml.NewDecoder(r)
	if err := dec.Decode(&feed); err != nil {
		return nil, err
	}

	var parsedIOCs []*ioc.IOC
	for _, item := range feed.Channel.Items {
		// Extract indicators from title and description
		content := item.Title + " " + item.Description

		// 1. Match IPs
		for _, ipStr := range ipRegex.FindAllString(content, -1) {
			score, _ := ioc.NewConfidenceScore(50) // Default score for OSINT RSS
			indicator := &ioc.IOC{
				ID:          "indicator--rss-ip-" + ipStr,
				Value:       ipStr,
				Type:        ioc.TypeIPv4,
				TLP:         ioc.TLPWhite,
				Confidence:  score,
				Description: "Parsed from RSS feed: " + item.Title,
				Tags:        []string{"osint", "rss"},
				IsActive:    true,
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			}
			if err := indicator.Validate(); err == nil {
				parsedIOCs = append(parsedIOCs, indicator)
			}
		}

		// 2. Match Hashes
		for _, hashStr := range hash256Reg.FindAllString(content, -1) {
			score, _ := ioc.NewConfidenceScore(75)
			indicator := &ioc.IOC{
				ID:          "indicator--rss-hash-" + hashStr,
				Value:       hashStr,
				Type:        ioc.TypeFileHash,
				TLP:         ioc.TLPWhite,
				Confidence:  score,
				Description: "Hash extracted from RSS item: " + item.Title,
				Tags:        []string{"osint", "rss", "malware"},
				IsActive:    true,
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			}
			if err := indicator.Validate(); err == nil {
				parsedIOCs = append(parsedIOCs, indicator)
			}
		}

		// 3. Match Domains
		for _, domainStr := range domainRegex.FindAllString(content, -1) {
			// Skip common domain prefixes
			domainStr = strings.ToLower(domainStr)
			if strings.HasSuffix(domainStr, ".png") || strings.HasSuffix(domainStr, ".jpg") || strings.HasSuffix(domainStr, ".html") || strings.HasSuffix(domainStr, ".xml") {
				continue
			}
			score, _ := ioc.NewConfidenceScore(40)
			indicator := &ioc.IOC{
				ID:          "indicator--rss-domain-" + domainStr,
				Value:       domainStr,
				Type:        ioc.TypeDomain,
				TLP:         ioc.TLPWhite,
				Confidence:  score,
				Description: "Domain extracted from RSS item: " + item.Title,
				Tags:        []string{"osint", "rss"},
				IsActive:    true,
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			}
			if err := indicator.Validate(); err == nil {
				parsedIOCs = append(parsedIOCs, indicator)
			}
		}
	}

	return parsedIOCs, nil
}
