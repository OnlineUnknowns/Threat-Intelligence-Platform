package ioc

import (
	"errors"
	"net"
	"regexp"
	"strings"
	"time"
)

var (
	cveRegex  = regexp.MustCompile(`^(?i)CVE-\d{4}-\d{4,7}$`)
	md5Regex  = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	sha1Regex = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)
	sha256Reg = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
)

// IOC represents an Indicator of Compromise aggregate root
type IOC struct {
	ID          string          `json:"id"`
	Value       string          `json:"value"`
	Type        IOCType         `json:"type"`
	TLP         TLP             `json:"tlp"`
	Confidence  ConfidenceScore `json:"confidence"`
	Description string          `json:"description"`
	Tags        []string        `json:"tags"`
	IsActive    bool            `json:"is_active"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	ExpiresAt   *time.Time      `json:"expires_at,omitempty"`
}

// Validate executes core business invariant rules for an IOC entity
func (i *IOC) Validate() error {
	i.Value = strings.TrimSpace(i.Value)
	if i.Value == "" {
		return errors.New("indicator value cannot be empty")
	}

	if !i.Type.IsValid() {
		return errors.New("invalid or unsupported indicator type")
	}

	if !i.TLP.IsValid() {
		return errors.New("invalid TLP classification")
	}

	switch i.Type {
	case TypeIPv4:
		ip := net.ParseIP(i.Value)
		if ip == nil || ip.To4() == nil {
			return errors.New("value is not a valid IPv4 address")
		}
	case TypeIPv6:
		ip := net.ParseIP(i.Value)
		if ip == nil || ip.To4() != nil {
			return errors.New("value is not a valid IPv6 address")
		}
	case TypeDomain:
		// Simple domain format validation
		if len(i.Value) < 3 || !strings.Contains(i.Value, ".") {
			return errors.New("value is not a valid domain name")
		}
	case TypeFileHash:
		if !md5Regex.MatchString(i.Value) && !sha1Regex.MatchString(i.Value) && !sha256Reg.MatchString(i.Value) {
			return errors.New("value is not a valid file hash (MD5, SHA-1, or SHA-256)")
		}
	case TypeCVE:
		if !cveRegex.MatchString(i.Value) {
			return errors.New("value is not a valid CVE identifier (e.g. CVE-2023-38606)")
		}
	case TypeURL:
		if !strings.HasPrefix(strings.ToLower(i.Value), "http://") && !strings.HasPrefix(strings.ToLower(i.Value), "https://") {
			return errors.New("url indicator must start with http:// or https://")
		}
	}

	return nil
}

// DefangedValue returns a neutralized string representation of the indicator value
// to prevent accidental execution/clicking by security analysts
func (i *IOC) DefangedValue() string {
	val := i.Value
	switch i.Type {
	case TypeIPv4, TypeIPv6:
		// 8.8.8.8 -> 8.8.8[.]8
		lastDot := strings.LastIndex(val, ".")
		if lastDot != -1 {
			return val[:lastDot] + "[.]" + val[lastDot+1:]
		}
		// IPv6 replacement of colon
		lastColon := strings.LastIndex(val, ":")
		if lastColon != -1 {
			return val[:lastColon] + "[:]" + val[lastColon+1:]
		}
	case TypeDomain:
		// evil.com -> evil[.]com
		lastDot := strings.LastIndex(val, ".")
		if lastDot != -1 {
			return val[:lastDot] + "[.]" + val[lastDot+1:]
		}
	case TypeURL:
		// http://evil.com/payload -> hxxp://evil[.]com/payload
		res := val
		if strings.HasPrefix(strings.ToLower(res), "https://") {
			res = "hxxps://" + res[8:]
		} else if strings.HasPrefix(strings.ToLower(res), "http://") {
			res = "hxxp://" + res[7:]
		}
		// Defang host part of URL
		hostStart := strings.Index(res, "://") + 3
		if hostStart > 2 {
			pathStart := strings.Index(res[hostStart:], "/")
			var host string
			var rest string
			if pathStart == -1 {
				host = res[hostStart:]
			} else {
				host = res[hostStart : hostStart+pathStart]
				rest = res[hostStart+pathStart:]
			}
			lastDot := strings.LastIndex(host, ".")
			if lastDot != -1 {
				host = host[:lastDot] + "[.]" + host[lastDot+1:]
			}
			return res[:hostStart] + host + rest
		}
	}
	return val
}
