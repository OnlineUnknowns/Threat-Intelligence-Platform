package relationship

import (
	"errors"
	"strings"
	"time"
)

// Relationship represents a STIX Relationship Object (SRO) linking two STIX Domain Objects (SDOs)
type Relationship struct {
	ID               string    `json:"id"`
	RelationshipType string    `json:"relationship_type"` // e.g., "indicates", "targets", "uses", "attributed-to"
	SourceRef        string    `json:"source_ref"`        // Source SDO ID (e.g., threat-actor--UUID)
	TargetRef        string    `json:"target_ref"`        // Target SDO ID (e.g., vulnerability--UUID)
	Description      string    `json:"description"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// Validate executes business rule validations for the Relationship entity
func (r *Relationship) Validate() error {
	if r.ID == "" {
		return errors.New("relationship ID cannot be empty")
	}
	r.RelationshipType = strings.TrimSpace(r.RelationshipType)
	if r.RelationshipType == "" {
		return errors.New("relationship type cannot be empty")
	}
	r.SourceRef = strings.TrimSpace(r.SourceRef)
	r.TargetRef = strings.TrimSpace(r.TargetRef)
	if r.SourceRef == "" || r.TargetRef == "" {
		return errors.New("source_ref and target_ref cannot be empty")
	}
	if r.SourceRef == r.TargetRef {
		return errors.New("cannot create self-referencing relationship")
	}
	return nil
}
