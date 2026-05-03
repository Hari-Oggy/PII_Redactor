package pii

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/enterprise/pii-gateway/pkg/models"
	nerpb "github.com/enterprise/pii-gateway/sidecar/ner"
	lru "github.com/hashicorp/golang-lru/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// NERDetector implements the Pipeline interface for machine-learning based
// Context-Aware PII detection, using an external gRPC sidecar.
type NERDetector struct {
	client  nerpb.NERServiceClient
	conn    *grpc.ClientConn
	cache   *lru.Cache[string, []models.PIIMatch]
	mu      sync.Mutex
	timeout time.Duration
}

// NewNERDetector creates a new gRPC client talking to the Python sidecar.
func NewNERDetector(target string, timeout time.Duration) (*NERDetector, error) {
	conn, err := grpc.Dial(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Printf("ERROR: failed to connect to NER sidecar at %s: %v", target, err)
	}

	client := nerpb.NewNERServiceClient(conn)
	cache, err := lru.New[string, []models.PIIMatch](10000)
	if err != nil {
		return nil, fmt.Errorf("create LRU cache: %w", err)
	}

	return &NERDetector{
		client:  client,
		conn:    conn,
		cache:   cache,
		timeout: timeout,
	}, nil
}

// Name returns a human-readable identifier for this detector.
func (d *NERDetector) Name() string {
	return "NER"
}

// Detect sends the text to the NER gRPC server with a strict timeout.
func (d *NERDetector) Detect(text string, _ time.Duration) []models.PIIMatch {
	if text == "" {
		return nil
	}

	// 1. Check LRU Cache
	if cached, ok := d.cache.Get(text); ok {
		return cached
	}

	// 2. Strict Timeout for the ML inference (Use NER specific timeout, not Regex timeout)
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()

	req := &nerpb.AnalyzeRequest{
		Text: text,
	}

	// 3. Perform gRPC Call
	resp, err := d.client.Analyze(ctx, req)
	if err != nil {
		// Log warning and fail-open.
		log.Printf("WARN: NER Sidecar failed (fail-open): %v", err)
		return nil
	}

	// 4. Map protobuf entities to internal PIIMatch structure
	matches := make([]models.PIIMatch, 0, len(resp.Entities))
	for _, entity := range resp.Entities {
		matches = append(matches, models.PIIMatch{
			Type:         entity.EntityType,
			Value:        text[entity.Start:entity.End],
			Start:        int(entity.Start),
			End:          int(entity.End),
			Confidence:   float64(entity.Score),
			DetectorName: "NER",
		})
	}

	// 5. Cache result and return
	d.cache.Add(text, matches)
	return matches
}

// Close cleans up the underlying gRPC connection.
func (d *NERDetector) Close() error {
	if d.conn != nil {
		return d.conn.Close()
	}
	return nil
}
