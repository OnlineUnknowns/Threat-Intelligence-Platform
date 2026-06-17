package stix

import (
	"encoding/json"
	"io"
	"time"

	"github.com/threat-intel-platform/internal/domain/actor"
	"github.com/threat-intel-platform/internal/domain/campaign"
	"github.com/threat-intel-platform/internal/domain/ioc"
	"github.com/threat-intel-platform/internal/domain/relationship"
	"github.com/threat-intel-platform/internal/domain/vulnerability"
)

type Bundle struct {
	Type        string            `json:"type"`
	ID          string            `json:"id"`
	SpecVersion string            `json:"spec_version"`
	Objects     []json.RawMessage `json:"objects"`
}

type CommonFields struct {
	Type        string    `json:"type"`
	ID          string    `json:"id"`
	Created     time.Time `json:"created"`
	Modified    time.Time `json:"modified"`
	Description string    `json:"description"`
}

type StixIndicator struct {
	CommonFields
	Name        string   `json:"name"`
	Pattern     string   `json:"pattern"`
	PatternType string   `json:"pattern_type"`
	Labels      []string `json:"labels"`
}

type StixThreatActor struct {
	CommonFields
	Name             string   `json:"name"`
	ThreatActorTypes []string `json:"threat_actor_types"`
	Aliases          []string `json:"aliases"`
	Goals            []string `json:"goals"`
	Sophistication   string   `json:"sophistication"`
}

type StixCampaign struct {
	CommonFields
	Name    string   `json:"name"`
	Aliases []string `json:"aliases"`
}

type StixVulnerability struct {
	CommonFields
	Name string `json:"name"` // CVSS score might be custom metadata
}

type StixRelationship struct {
	CommonFields
	RelationshipType string `json:"relationship_type"`
	SourceRef        string `json:"source_ref"`
	TargetRef        string `json:"target_ref"`
}

type StixObjects struct {
	Indicators      []*ioc.IOC
	ThreatActors    []*actor.ThreatActor
	Campaigns       []*campaign.Campaign
	Vulnerabilities []*vulnerability.Vulnerability
	Relationships   []*relationship.Relationship
}

// ParseBundle decodes a STIX 2.1 JSON bundle and normalizes its objects into core domain models
func ParseBundle(r io.Reader) (*StixObjects, error) {
	var bundle Bundle
	dec := json.NewDecoder(r)
	if err := dec.Decode(&bundle); err != nil {
		return nil, err
	}

	result := &StixObjects{}

	for _, rawObj := range bundle.Objects {
		var common CommonFields
		if err := json.Unmarshal(rawObj, &common); err != nil {
			continue
		}

		switch common.Type {
		case "indicator":
			var sInd StixIndicator
			if err := json.Unmarshal(rawObj, &sInd); err == nil {
				score, _ := ioc.NewConfidenceScore(70) // Standard default
				// Deduce value from pattern (standard STIX e.g. "[ipv4-addr:value = '1.1.1.1']")
				value := extractValueFromPattern(sInd.Pattern)
				if value == "" {
					value = sInd.Name
				}
				iocType := ioc.TypeIPv4
				if sInd.PatternType == "yara" || sInd.PatternType == "sigma" {
					iocType = ioc.TypeFileHash
				}

				ind := &ioc.IOC{
					ID:          sInd.ID,
					Value:       value,
					Type:        iocType,
					TLP:         ioc.TLPWhite,
					Confidence:  score,
					Description: sInd.Description,
					Tags:        sInd.Labels,
					IsActive:    true,
					CreatedAt:   sInd.Created,
					UpdatedAt:   sInd.Modified,
				}
				if err := ind.Validate(); err == nil {
					result.Indicators = append(result.Indicators, ind)
				}
			}

		case "threat-actor":
			var sActor StixThreatActor
			if err := json.Unmarshal(rawObj, &sActor); err == nil {
				ta := &actor.ThreatActor{
					ID:               sActor.ID,
					Name:             sActor.Name,
					Description:      sActor.Description,
					ThreatActorTypes: sActor.ThreatActorTypes,
					Aliases:          sActor.Aliases,
					Sophistication:   sActor.Sophistication,
					Goals:            sActor.Goals,
					CreatedAt:        sActor.Created,
					UpdatedAt:        sActor.Modified,
					IsActive:         true,
				}
				if err := ta.Validate(); err == nil {
					result.ThreatActors = append(result.ThreatActors, ta)
				}
			}

		case "campaign":
			var sCamp StixCampaign
			if err := json.Unmarshal(rawObj, &sCamp); err == nil {
				c := &campaign.Campaign{
					ID:          sCamp.ID,
					Name:        sCamp.Name,
					Description: sCamp.Description,
					Aliases:     sCamp.Aliases,
					CreatedAt:   sCamp.Created,
					UpdatedAt:   sCamp.Modified,
					IsActive:    true,
				}
				if err := c.Validate(); err == nil {
					result.Campaigns = append(result.Campaigns, c)
				}
			}

		case "vulnerability":
			var sVuln StixVulnerability
			if err := json.Unmarshal(rawObj, &sVuln); err == nil {
				v := &vulnerability.Vulnerability{
					ID:          sVuln.ID,
					CVE:         sVuln.Name, // STIX maps the CVE id to the name property
					Description: sVuln.Description,
					CreatedAt:   sVuln.Created,
					UpdatedAt:   sVuln.Modified,
				}
				if err := v.Validate(); err == nil {
					result.Vulnerabilities = append(result.Vulnerabilities, v)
				}
			}

		case "relationship":
			var sRel StixRelationship
			if err := json.Unmarshal(rawObj, &sRel); err == nil {
				r := &relationship.Relationship{
					ID:               sRel.ID,
					RelationshipType: sRel.RelationshipType,
					SourceRef:        sRel.SourceRef,
					TargetRef:        sRel.TargetRef,
					Description:      sRel.Description,
					CreatedAt:        sRel.Created,
					UpdatedAt:        sRel.Modified,
				}
				if err := r.Validate(); err == nil {
					result.Relationships = append(result.Relationships, r)
				}
			}
		}
	}

	return result, nil
}

// Basic helper to extract values from STIX patterns e.g. "[ipv4-addr:value = '192.168.1.1']"
func extractValueFromPattern(pattern string) string {
	var val string
	quoteStarted := false
	for _, char := range pattern {
		if char == '\'' {
			if quoteStarted {
				break
			}
			quoteStarted = true
			continue
		}
		if quoteStarted {
			val += string(char)
		}
	}
	return val
}
