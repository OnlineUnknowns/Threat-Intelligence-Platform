package ioc

import (
	"errors"
	"fmt"
	"strings"
)

// IOCType defines the categorization of the indicator
type IOCType string

const (
	TypeIPv4     IOCType = "ipv4"
	TypeIPv6     IOCType = "ipv6"
	TypeDomain   IOCType = "domain"
	TypeURL      IOCType = "url"
	TypeFileHash IOCType = "file_hash" // md5, sha1, sha256
	TypeCVE      IOCType = "cve"
)

// IsValid checks if the given type is supported
func (t IOCType) IsValid() bool {
	switch t {
	case TypeIPv4, TypeIPv6, TypeDomain, TypeURL, TypeFileHash, TypeCVE:
		return true
	}
	return false
}

// TLP (Traffic Light Protocol) defines the data sharing classification
type TLP string

const (
	TLPWhite TLP = "WHITE"
	TLPGreen TLP = "GREEN"
	TLPAmber TLP = "AMBER"
	TLPRed   TLP = "RED"
)

// IsValid checks if the TLP level is standard
func (t TLP) IsValid() bool {
	switch t {
	case TLPWhite, TLPGreen, TLPAmber, TLPRed:
		return true
	}
	return false
}

// ParseTLP parses a string into a valid TLP level
func ParseTLP(val string) (TLP, error) {
	upper := TLP(strings.ToUpper(strings.TrimSpace(val)))
	if !upper.IsValid() {
		return "", fmt.Errorf("invalid TLP level: %s", val)
	}
	return upper, nil
}

// ConfidenceScore represents a value between 0 and 100
type ConfidenceScore int

// NewConfidenceScore constructs and validates a score
func NewConfidenceScore(val int) (ConfidenceScore, error) {
	if val < 0 || val > 100 {
		return 0, errors.New("confidence score must be between 0 and 100")
	}
	return ConfidenceScore(val), nil
}

// Int returns the raw score integer
func (c ConfidenceScore) Int() int {
	return int(c)
}
