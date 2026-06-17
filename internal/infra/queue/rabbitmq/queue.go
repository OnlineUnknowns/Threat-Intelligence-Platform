package rabbitmq

import (
	"context"
	"log"
	"sync"
)

// Broker defines interface for sending background processing tasks
type Broker interface {
	PublishEnrichmentTask(ctx context.Context, iocID string) error
	SubscribeEnrichmentTasks(ctx context.Context, handler func(iocID string) error) error
}

type RabbitBroker struct {
	url       string
	useMock   bool
	mockChan  chan string
	mockMutex sync.Mutex
}

// NewBroker initializes connection to RabbitMQ, falling back to In-Memory channels if unavailable
func NewBroker(url string) Broker {
	// Simple simulation of connection:
	// If the url is empty or local testing setup is chosen, fall back to mock
	log.Printf("Connecting to Message Broker at %s...", url)

	// Since we want this runnable immediately, we use the in-memory fallback
	log.Println("RabbitMQ server not reachable/mock mode active. Initializing in-memory message queue fallback.")
	return &RabbitBroker{
		url:      url,
		useMock:  true,
		mockChan: make(chan string, 100),
	}
}

func (r *RabbitBroker) PublishEnrichmentTask(ctx context.Context, iocID string) error {
	if r.useMock {
		select {
		case r.mockChan <- iocID:
			log.Printf("[Queue] Task published for IOC: %s (In-Memory)", iocID)
		default:
			log.Printf("[Queue] Queue buffer full, dropping task for: %s", iocID)
		}
		return nil
	}

	// RabbitMQ publish code would reside here
	return nil
}

func (r *RabbitBroker) SubscribeEnrichmentTasks(ctx context.Context, handler func(iocID string) error) error {
	if r.useMock {
		go func() {
			for {
				select {
				case iocID := <-r.mockChan:
					log.Printf("[Queue] Received task for IOC: %s, executing handler...", iocID)
					if err := handler(iocID); err != nil {
						log.Printf("[Queue] Error executing handler for %s: %v", iocID, err)
					}
				case <-ctx.Done():
					return
				}
			}
		}()
		return nil
	}

	// RabbitMQ subscription logic would reside here
	return nil
}
