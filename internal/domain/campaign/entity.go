package campaign

import (
	"errors"
	"strings"
	"time"
)

// Campaign represents a grouping of adversarial behaviors targeting a set of objectives (STIX SDO)
type Campaign struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Aliases     []string   `json:"aliases"`
	FirstSeen   *time.Time `json:"first_seen,omitempty"`
	LastSeen    *time.Time `json:"last_seen,omitempty"`
	Objective   string     `json:"objective"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	IsActive    bool       `json:"is_active"`
}

// Validate executes business rule validations for the Campaign entity
func (c *Campaign) Validate() error {
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" {
		return errors.New("campaign name cannot be empty")
	}
	if c.ID == "" {
		return errors.New("campaign ID cannot be empty")
	}
	if c.FirstSeen != nil && c.LastSeen != nil && c.FirstSeen.After(*c.LastSeen) {
		return errors.New("first_seen time cannot be after last_seen time")
	}
	return nil
}
