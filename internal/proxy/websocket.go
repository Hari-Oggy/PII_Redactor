package proxy

import (
	"context"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/enterprise/pii-gateway/internal/middleware"
	"github.com/enterprise/pii-gateway/internal/pii"
	"github.com/gorilla/websocket"
	"strings"
)

// SafeWebSocket wraps a gorilla/websocket connection with a mutex
// to prevent concurrent write panics, which is a known flaw in gorilla/ws.
type SafeWebSocket struct {
	mu   sync.Mutex
	conn *websocket.Conn
}

func (s *SafeWebSocket) WriteMessage(messageType int, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn.WriteMessage(messageType, data)
}

func (s *SafeWebSocket) WriteControl(messageType int, data []byte, deadline time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn.WriteControl(messageType, data, deadline)
}

// WebSocketProxy handles bidirectional streaming and PII redaction for WebSockets.
type WebSocketProxy struct {
	pipeline *pii.Pipeline
	redactor *pii.Redactor
	upgrader websocket.Upgrader
}

// NewWebSocketProxy creates a new WebSocketProxy.
func NewWebSocketProxy(pipeline *pii.Pipeline, redactor *pii.Redactor) *WebSocketProxy {
	return &WebSocketProxy{
		pipeline: pipeline,
		redactor: redactor,
		upgrader: websocket.Upgrader{
			// Allow any origin for this demo; in production consider restricting.
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

// Proxy establishes the connection and pumps messages in both directions.
func (wp *WebSocketProxy) Proxy(w http.ResponseWriter, r *http.Request, upstreamURL string, tokenMap pii.TokenMap, uctx middleware.UserContext, requestID string) {
	// Upgrade external client connection
	clientConn, err := wp.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[%s] WS Upgrade error: %v", requestID, err)
		return
	}
	defer clientConn.Close()

	// Enforce 2MB max frame size to prevent OOM
	clientConn.SetReadLimit(2 * 1024 * 1024)

	safeClientConn := &SafeWebSocket{conn: clientConn}

	// Connect to upstream LLM WebSocket
	// Pass the token along if needed, or API keys depending on the upgrader
	// For simplicity, we dial the upstream with an empty header.
	upstreamConn, resp, err := websocket.DefaultDialer.Dial(upstreamURL, nil)
	if err != nil {
		log.Printf("[%s] Upstream WS connect error: %v", requestID, err)
		if resp != nil {
			body, _ := io.ReadAll(resp.Body)
			log.Printf("Upstream WS response: %s", body)
		}
		safeClientConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "upstream connection failed"))
		return
	}
	defer upstreamConn.Close()

	// Enforce 2MB max frame size on upstream as well
	upstreamConn.SetReadLimit(2 * 1024 * 1024)

	safeUpstreamConn := &SafeWebSocket{conn: upstreamConn}

	// Create cancellation context for bi-directional pump
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Pump client -> upstream (requests)
	go wp.pump(ctx, safeClientConn, safeUpstreamConn, tokenMap, uctx, requestID, "client->upstream", cancel)

	// Pump upstream -> client (responses)
	go wp.pump(ctx, safeUpstreamConn, safeClientConn, tokenMap, uctx, requestID, "upstream->client", cancel)

	// Wait for context cancellation
	<-ctx.Done()
}

// pump reads from src, redacts PII, and writes to dst.
func (wp *WebSocketProxy) pump(
	ctx context.Context, src, dst *SafeWebSocket, tokenMap pii.TokenMap, uctx middleware.UserContext, reqID, direction string, cancel context.CancelFunc,
) {
	defer cancel() // Cancel context when either pump terminates

	for {
		// Read message
		msgType, msg, err := src.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("[%s] WS %s read error: %v", reqID, direction, err)
			}
			break
		}

		// Only redact Text messages. We pass Binary messages intact.
		if msgType == websocket.TextMessage {
			text := string(msg)

			// 1. Detect PII
			matches := wp.pipeline.Detect(text)

			// 2. Redact if matches found
			if len(matches) > 0 {
				redacted, spans := wp.redactor.Redact(text, matches, tokenMap, uctx)
				msg = []byte(redacted)

				log.Printf("[%s] WS %s: detected %d PII items", reqID, direction, len(spans))
				for _, s := range spans {
					middleware.RecordPIIDetection(s.Type, s.DetectorName)
				}
			}
		}

		// Write message
		if err := dst.WriteMessage(msgType, msg); err != nil {
			log.Printf("[%s] WS %s write error: %v", reqID, direction, err)
			break
		}
	}

	// Send close message gracefully
	dst.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
}

// StreamReqToURL builds a WS URL out of the original proxy request.
func StreamReqToURL(req *http.Request, providerBaseURL, providerPathPrefix string) string {
	// Reconstruct the UPSTREAM URL replacing HTTP(S) with WS(S)
	scheme := "ws"
	if strings.HasPrefix(providerBaseURL, "https") {
		scheme = "wss"
	}

	hostPort := strings.TrimPrefix(providerBaseURL, "https://")
	hostPort = strings.TrimPrefix(hostPort, "http://")

	upstreamPath := strings.TrimPrefix(req.URL.Path, providerPathPrefix)
	
	url := scheme + "://" + hostPort + upstreamPath
	if req.URL.RawQuery != "" {
		url += "?" + req.URL.RawQuery
	}
	return url
}
