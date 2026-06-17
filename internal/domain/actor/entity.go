package actor

import (
	"errors"
	"strings"
	"time"
)

// ThreatActor represents the adversary's profile, identities, and motivations (STIX SDO)
type ThreatActor struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	Description        string    `json:"description"`
	ThreatActorTypes   []string  `json:"threat_actor_types"` // e.g., "nation-state", "hacktivist"
	Aliases            []string  `json:"aliases"`
	Roles              []string  `json:"roles"`
	Goals              []string  `json:"goals"`
	Sophistication     string    `json:"sophistication"` // e.g., "advanced", "expert"
	ResourceLevel      string    `json:"resource_level"` // e.g., "government", "organization"
	PrimaryMotivation  string    `json:"primary_motivation"`
	SecondaryMotiv          []string  `json:"secondary_motivations"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
	IsActive           bool      `json:"is_active"`
}

// Validate executes business rule validations for the ThreatActor entity
func (ta *ThreatActor) Validate() error {
	ta.Name = strings.TrimSpace(ta.Name)
	if ta.Name == "" {
		return errors.New("threat actor name cannot be empty")
	}
	if ta.ID == "" {
		return errors.New("threat actor ID cannot be empty")
	}
	return nil
}
