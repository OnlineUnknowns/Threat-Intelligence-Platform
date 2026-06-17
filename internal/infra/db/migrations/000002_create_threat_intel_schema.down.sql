-- Revert core threat intelligence schema

DROP TABLE IF EXISTS relationships;
DROP TABLE IF EXISTS sightings;
DROP TABLE IF EXISTS vulnerabilities;
DROP TABLE IF EXISTS campaigns;
DROP TABLE IF EXISTS threat_actors;
DROP TABLE IF EXISTS indicators;
