package v1

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/threat-intel-platform/internal/app/ingest"
	"github.com/threat-intel-platform/internal/domain/ioc"
	"github.com/threat-intel-platform/internal/infra/queue/rabbitmq"
)

type APIHandlers struct {
	repo          ioc.Repository
	ingestService *ingest.IngestService
	broker        rabbitmq.Broker
}

func NewAPIHandlers(repo ioc.Repository, ingestService *ingest.IngestService, broker rabbitmq.Broker) *APIHandlers {
	return &APIHandlers{
		repo:          repo,
		ingestService: ingestService,
		broker:        broker,
	}
}

type CreateIOCRequest struct {
	Value       string `json:"value"`
	Type        string `json:"type"`
	TLP         string `json:"tlp"`
	Confidence  int    `json:"confidence"`
	Description string `json:"description"`
	Tags        []string `json:"tags"`
}

type IOCResponse struct {
	ID            string   `json:"id"`
	Value         string   `json:"value"`
	DefangedValue string   `json:"defanged_value"` // Neutralized representation
	Type          string   `json:"type"`
	TLP           string   `json:"tlp"`
	Confidence    int      `json:"confidence"`
	Description   string   `json:"description"`
	Tags          []string `json:"tags"`
	IsActive      bool     `json:"is_active"`
	CreatedAt     string   `json:"created_at"`
}

func (h *APIHandlers) CreateIOC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CreateIOCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	score, err := ioc.NewConfidenceScore(req.Confidence)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	tlpParsed, err := ioc.ParseTLP(req.TLP)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Make simulated ID
	uuid := "indicator--" + strings.ToLower(req.Type) + "-" + strings.ReplaceAll(req.Value, ".", "-")
	item := &ioc.IOC{
		ID:          uuid,
		Value:       req.Value,
		Type:        ioc.IOCType(req.Type),
		TLP:         tlpParsed,
		Confidence:  score,
		Description: req.Description,
		Tags:        req.Tags,
		IsActive:    true,
	}

	if err := item.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.repo.Create(r.Context(), item); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	// Publish to queue for worker enrichment
	_ = h.broker.PublishEnrichmentTask(r.Context(), item.ID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(mapToResponse(item))
}

func (h *APIHandlers) GetIOC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Basic route param parsing for standard Go router
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 5 {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	id := pathParts[4]

	item, err := h.repo.GetByID(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(mapToResponse(item))
}

func (h *APIHandlers) SearchIOCs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	queryVals := r.URL.Query()
	query := queryVals.Get("query")
	typeStr := queryVals.Get("type")

	var types []ioc.IOCType
	if typeStr != "" {
		for _, t := range strings.Split(typeStr, ",") {
			types = append(types, ioc.IOCType(strings.TrimSpace(t)))
		}
	}

	items, err := h.repo.Search(r.Context(), query, types, 100, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var responseList []IOCResponse
	for _, item := range items {
		responseList = append(responseList, mapToResponse(item))
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(responseList)
}

func (h *APIHandlers) RunIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()
	log.Println("[API] Manually triggering threat feed ingestion...")

	// Run RSS ingestion
	if err := h.ingestService.IngestFromRSS(ctx, ingest.SampleRSSFeed()); err != nil {
		http.Error(w, "RSS Ingest Failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Run STIX ingestion
	if err := h.ingestService.IngestFromSTIX(ctx, ingest.SampleSTIXBundle()); err != nil {
		http.Error(w, "STIX Ingest Failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"success","message":"RSS and STIX feeds successfully ingested, enrichment tasks queued"}`))
}

func mapToResponse(item *ioc.IOC) IOCResponse {
	return IOCResponse{
		ID:            item.ID,
		Value:         item.Value,
		DefangedValue: item.DefangedValue(), // Defanged value for secure API transport
		Type:          string(item.Type),
		TLP:           string(item.TLP),
		Confidence:    item.Confidence.Int(),
		Description:   item.Description,
		Tags:          item.Tags,
		IsActive:      item.IsActive,
		CreatedAt:     item.CreatedAt.Format(http.TimeFormat),
	}
}
