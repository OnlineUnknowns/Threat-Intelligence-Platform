package http

import (
	"log"
	"net/http"
	"time"

	v1 "github.com/threat-intel-platform/internal/presentation/http/v1"
)

// SetupRouter binds handlers to standard HTTP endpoints and wraps them with tracking middleware
func SetupRouter(handlers *v1.APIHandlers) http.Handler {
	mux := http.NewServeMux()

	// Public Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	})

	// V1 Protected Routes
	mux.HandleFunc("/api/v1/ioc", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			handlers.CreateIOC(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Standard Go ServeMux doesn't do wildcards natively without custom parsing
	mux.HandleFunc("/api/v1/ioc/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/ioc/search" {
			handlers.SearchIOCs(w, r)
		} else {
			handlers.GetIOC(w, r)
		}
	})

	// Manual Trigger for Feeds Ingestion
	mux.HandleFunc("/api/v1/ingest/run", handlers.RunIngest)

	// Wrap routing in security, rate-limiting and audit logging middlewares
	return auditLogger(authMiddleware(rateLimiter(mux)))
}

func auditLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("[AuditLog] %s %s from %s took %v", r.Method, r.URL.Path, r.RemoteAddr, time.Since(start))
	})
}

func rateLimiter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mock token-bucket check
		// In production, we connect to Redis and enforce limits based on the X-API-KEY header
		next.ServeHTTP(w, r)
	})
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Basic token security validation check (X-API-KEY)
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" && r.URL.Path != "/health" {
			log.Printf("[Security] Unauthorized attempt to access %s", r.URL.Path)
			http.Error(w, "Unauthorized: Missing X-API-Key header", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
