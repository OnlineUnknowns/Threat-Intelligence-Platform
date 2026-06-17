package ioc

import (
	"context"
)

// Repository defines the storage contract for persisting and retrieving indicators (DDD Port)
type Repository interface {
	Create(ctx context.Context, ioc *IOC) error
	GetByID(ctx context.Context, id string) (*IOC, error)
	GetByValue(ctx context.Context, value string) (*IOC, error)
	Update(ctx context.Context, ioc *IOC) error
	Delete(ctx context.Context, id string) error
	Search(ctx context.Context, query string, types []IOCType, limit int, offset int) ([]*IOC, error)
}
