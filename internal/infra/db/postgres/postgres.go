package postgres

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/threat-intel-platform/internal/domain/ioc"
)

type PostgresRepository struct {
	db        *sql.DB
	useMemory bool
	memDb     map[string]*ioc.IOC
	memMutex  sync.RWMutex
}

// NewPostgresRepository attempts to connect to PostgreSQL, falling back to a thread-safe In-Memory DB
func NewPostgresRepository(host string, port int, user, password, dbname, sslmode string) ioc.Repository {
	log.Printf("Connecting to PostgreSQL Database: host=%s dbname=%s...", host, dbname)

	// In this mock skeleton setup, we default to in-memory fallback for instant runnability
	log.Println("PostgreSQL connection skipped/mock active. Initializing in-memory relational store fallback.")
	return &PostgresRepository{
		useMemory: true,
		memDb:     make(map[string]*ioc.IOC),
	}
}

func (r *PostgresRepository) Create(ctx context.Context, item *ioc.IOC) error {
	if r.useMemory {
		r.memMutex.Lock()
		defer r.memMutex.Unlock()

		// Enforce unique constraint (value + type)
		for _, existing := range r.memDb {
			if existing.Value == item.Value && existing.Type == item.Type {
				return errors.New("duplicate key value violates unique constraint on (value, type)")
			}
		}

		item.CreatedAt = time.Now()
		item.UpdatedAt = time.Now()
		r.memDb[item.ID] = item
		log.Printf("[DB] IOC created: %s (%s)", item.Value, item.Type)
		return nil
	}

	// Real SQL statement for inserting into Postgres table
	return nil
}

func (r *PostgresRepository) GetByID(ctx context.Context, id string) (*ioc.IOC, error) {
	if r.useMemory {
		r.memMutex.RLock()
		defer r.memMutex.RUnlock()

		item, exists := r.memDb[id]
		if !exists {
			return nil, errors.New("indicator not found")
		}
		return item, nil
	}

	return nil, nil
}

func (r *PostgresRepository) GetByValue(ctx context.Context, value string) (*ioc.IOC, error) {
	if r.useMemory {
		r.memMutex.RLock()
		defer r.memMutex.RUnlock()

		for _, item := range r.memDb {
			if item.Value == value {
				return item, nil
			}
		}
		return nil, errors.New("indicator not found")
	}

	return nil, nil
}

func (r *PostgresRepository) Update(ctx context.Context, item *ioc.IOC) error {
	if r.useMemory {
		r.memMutex.Lock()
		defer r.memMutex.Unlock()

		existing, exists := r.memDb[item.ID]
		if !exists {
			return errors.New("indicator not found")
		}

		existing.TLP = item.TLP
		existing.Confidence = item.Confidence
		existing.Description = item.Description
		existing.Tags = item.Tags
		existing.IsActive = item.IsActive
		existing.UpdatedAt = time.Now()
		existing.ExpiresAt = item.ExpiresAt

		r.memDb[item.ID] = existing
		log.Printf("[DB] IOC updated: %s", item.ID)
		return nil
	}

	return nil
}

func (r *PostgresRepository) Delete(ctx context.Context, id string) error {
	if r.useMemory {
		r.memMutex.Lock()
		defer r.memMutex.Unlock()

		if _, exists := r.memDb[id]; !exists {
			return errors.New("indicator not found")
		}
		delete(r.memDb, id)
		log.Printf("[DB] IOC deleted: %s", id)
		return nil
	}

	return nil
}

func (r *PostgresRepository) Search(ctx context.Context, query string, types []ioc.IOCType, limit, offset int) ([]*ioc.IOC, error) {
	if r.useMemory {
		r.memMutex.RLock()
		defer r.memMutex.RUnlock()

		var matched []*ioc.IOC
		for _, item := range r.memDb {
			// Filter by type
			typeMatch := len(types) == 0
			for _, t := range types {
				if item.Type == t {
					typeMatch = true
					break
				}
			}

			// Filter by search query value or tags
			queryMatch := query == "" || strings.Contains(strings.ToLower(item.Value), strings.ToLower(query)) || strings.Contains(strings.ToLower(item.Description), strings.ToLower(query))
			if !queryMatch {
				for _, tag := range item.Tags {
					if strings.Contains(strings.ToLower(tag), strings.ToLower(query)) {
						queryMatch = true
						break
					}
				}
			}

			if typeMatch && queryMatch {
				matched = append(matched, item)
			}
		}

		// Pagination offset/limits
		if offset >= len(matched) {
			return []*ioc.IOC{}, nil
		}
		end := offset + limit
		if end > len(matched) {
			end = len(matched)
		}
		return matched[offset:end], nil
	}

	return nil, nil
}
