package sighting

import (
	"errors"
	"strings"
	"time"
)

// Sighting represents an observation of threat indicators or vulnerabilities (STIX SDO)
type Sighting struct {
	ID             string     `json:"id"`
	SightingOfRef  string     `json:"sighting_of_ref"` // ID of the IOC or Vulnerability observed
	WhereSighted   string     `json:"where_sighted"`   // E.g., target industry, sector, or client region
	FirstSeen      time.Time  `json:"first_seen"`
	LastSeen       time.Time  `json:"last_seen"`
	Count          int        `json:"count"`
	Summary        string     `json:"summary"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// Validate executes business rule validations for the Sighting entity
func (s *Sighting) Validate() error {
	if s.ID == "" {
		return errors.New("sighting ID cannot be empty")
	}
	s.SightingOfRef = strings.TrimSpace(s.SightingOfRef)
	if s.SightingOfRef == "" {
		return errors.New("sighting must reference a target entity (sighting_of_ref)")
	}
	if s.Count < 1 {
		return errors.New("sighting count must be at least 1")
	}
	if s.FirstSeen.After(s.LastSeen) {
		return errors.New("first_seen time cannot be after last_seen time")
	}
	return nil
}
