-- Phase 2: Create Threat Intelligence Core Schema (STIX 2.1 aligned)

-- 1. Core indicators table (Massive IOC writes)
CREATE TABLE IF NOT EXISTS indicators (
    id VARCHAR(255) PRIMARY KEY,
    value TEXT NOT NULL,
    type VARCHAR(50) NOT NULL,
    tlp VARCHAR(20) NOT NULL DEFAULT 'WHITE',
    confidence INT NOT NULL DEFAULT 0,
    description TEXT,
    tags TEXT[] DEFAULT '{}',
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    expires_at TIMESTAMPTZ,
    raw_payload JSONB,
    CONSTRAINT chk_confidence CHECK (confidence >= 0 AND confidence <= 100)
);

-- Unique constraint on indicator value + type (since different types can have same value, e.g. a file hash and domain/url)
CREATE UNIQUE INDEX IF NOT EXISTS idx_indicators_value_type ON indicators (value, type);
CREATE INDEX IF NOT EXISTS idx_indicators_type ON indicators (type);
CREATE INDEX IF NOT EXISTS idx_indicators_tlp ON indicators (tlp);
CREATE INDEX IF NOT EXISTS idx_indicators_is_active ON indicators (is_active);
CREATE INDEX IF NOT EXISTS idx_indicators_created_at ON indicators (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_indicators_tags ON indicators USING gin (tags);
CREATE INDEX IF NOT EXISTS idx_indicators_raw_payload ON indicators USING gin (raw_payload);

-- 2. Threat Actors table
CREATE TABLE IF NOT EXISTS threat_actors (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    threat_actor_types TEXT[] DEFAULT '{}',
    aliases TEXT[] DEFAULT '{}',
    roles TEXT[] DEFAULT '{}',
    goals TEXT[] DEFAULT '{}',
    sophistication VARCHAR(50),
    resource_level VARCHAR(50),
    primary_motivation VARCHAR(100),
    secondary_motivations TEXT[] DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    raw_payload JSONB
);

CREATE INDEX IF NOT EXISTS idx_threat_actors_name ON threat_actors (name);
CREATE INDEX IF NOT EXISTS idx_threat_actors_aliases ON threat_actors USING gin (aliases);

-- 3. Campaigns table
CREATE TABLE IF NOT EXISTS campaigns (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    aliases TEXT[] DEFAULT '{}',
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    objective TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    raw_payload JSONB
);

CREATE INDEX IF NOT EXISTS idx_campaigns_name ON campaigns (name);

-- 4. Vulnerabilities table (CVEs)
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id VARCHAR(255) PRIMARY KEY,
    cve VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    cvss_v3_score NUMERIC(4, 2),
    cvss_v3_vector VARCHAR(255),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    raw_payload JSONB,
    CONSTRAINT chk_cvss_score CHECK (cvss_v3_score >= 0.0 AND cvss_v3_score <= 10.0)
);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve ON vulnerabilities (cve);

-- 5. Sightings table
CREATE TABLE IF NOT EXISTS sightings (
    id VARCHAR(255) PRIMARY KEY,
    sighting_of_ref VARCHAR(255) NOT NULL,
    where_sighted VARCHAR(255),
    first_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    count INT DEFAULT 1 NOT NULL,
    summary TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    raw_payload JSONB,
    CONSTRAINT chk_count CHECK (count >= 1)
);

CREATE INDEX IF NOT EXISTS idx_sightings_ref ON sightings (sighting_of_ref);
CREATE INDEX IF NOT EXISTS idx_sightings_first_seen ON sightings (first_seen DESC);

-- 6. Relationships table (STIX SRO mapping nodes to edges)
CREATE TABLE IF NOT EXISTS relationships (
    id VARCHAR(255) PRIMARY KEY,
    relationship_type VARCHAR(100) NOT NULL,
    source_ref VARCHAR(255) NOT NULL,
    target_ref VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    raw_payload JSONB,
    CONSTRAINT chk_self_reference CHECK (source_ref <> target_ref)
);

-- Fast lookup indexes for bidirectional graph queries and relationship lookups
CREATE INDEX IF NOT EXISTS idx_relationships_source ON relationships (source_ref);
CREATE INDEX IF NOT EXISTS idx_relationships_target ON relationships (target_ref);
CREATE INDEX IF NOT EXISTS idx_relationships_source_type ON relationships (source_ref, relationship_type);
CREATE INDEX IF NOT EXISTS idx_relationships_target_type ON relationships (target_ref, relationship_type);
CREATE UNIQUE INDEX IF NOT EXISTS idx_relationships_uniq ON relationships (source_ref, target_ref, relationship_type);
