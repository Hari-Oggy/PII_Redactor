# PII Redactor API Gateway — Walkthrough

## Overview

Built a **Privacy-First API Gateway for LLMs** in Go — an enterprise proxy that intercepts requests to external AI APIs (OpenAI, Anthropic, Azure), scrubs PII from the request, forwards the sanitised request, scans the response for new PII, re-hydrates legitimate tokens, and returns the clean response.

## Planning (3 iterations, 23 security fixes)

The architecture went through **3 self-critique iterations** before implementation:

| Phase | Flaws Found | Key Fixes |
|---|---|---|
| v1 → v2 | 12 | HMAC token signing, streaming overlap buffer, response PII scanning, body size limits, context-scoped token map, chi router (gorilla/mux archived) |
| v2 → v3 | 11 | ReDoS protection (50ms timeout), header/query PII scan, admin on separate port, LLM error response scanning, configurable overlap buffer, upstream timeout, health probes, atomic config reload, correlation IDs |

> [!NOTE]
> Full plan with architecture diagrams: [implementation_plan.md](file:///C:/Users/akhil/.gemini/antigravity/brain/2ac4641e-3a1b-42ad-b1b1-3692cadcbcbc/implementation_plan.md)

## Implementation — 30 files across 9 packages

### Project Structure

```
c:\Program1\sysMon\
├── cmd/gateway/main.go
├── internal/
│   ├── config/config.go         — atomic.Pointer copy-on-write hot-reload
│   ├── server/server.go         — dual-port (proxy :8080 + admin :9090)
│   ├── proxy/handler.go         — full inbound→outbound→response pipeline
│   ├── proxy/streaming.go       — SSE overlap buffer proxy
│   ├── provider/adapter.go      — provider adapter interface + registry
│   ├── provider/openai.go       — OpenAI normaliser
│   ├── provider/anthropic.go    — Anthropic normaliser
│   ├── provider/azure.go        — Azure (delegates to OpenAI)
│   ├── provider/circuitbreaker.go — per-provider gobreaker
│   ├── middleware/ (8 files)    — correlation, auth, ratelimit, bodylimit,
│   │                              headerscan, logging, metrics, recovery
│   ├── pii/ (9 files + 3 tests) — tokenmap, detector, regex, blocklist,
│   │                               allowlist, confidence, redactor,
│   │                               rehydrator, overlap
│   ├── admin/handler.go         — healthz, readyz, blocklist CRUD
│   └── audit/logger.go          — JSON audit trail
├── pkg/models/types.go
├── config.yaml, Makefile, Dockerfile
```

### Key Architecture Highlights

- **HMAC-Signed Tokens** — `crypto/rand` UUID + `HMAC-SHA256` prevents LLM token injection
- **Concurrent PII Pipeline** — Multiple detectors (regex, blocklist) run in parallel with per-detector timeout
- **Streaming Overlap Buffer** — Configurable (default 128B) sliding window catches PII split across SSE chunks
- **Circuit Breaker** — Per-provider (`gobreaker`) in the provider layer, not middleware
- **Atomic Config Reload** — `atomic.Pointer[Config]` copy-on-write swap via Viper + fsnotify
- **Dual-Port Server** — Proxy (:8080) isolated from admin (:9090 loopback only)
- **Bounded Concurrency** — Semaphore channel caps in-flight requests at 10,000

## Verification Results

### Build
```
go build ./... → ✅ Zero errors
```

### Tests — 13/13 passing

| Test | Result |
|---|---|
| [TestRegexDetector_Email](file:///c:/Program1/sysMon/internal/pii/regex_test.go#9-28) | ✅ |
| [TestRegexDetector_SSN](file:///c:/Program1/sysMon/internal/pii/regex_test.go#29-48) | ✅ |
| [TestRegexDetector_AWSKey](file:///c:/Program1/sysMon/internal/pii/regex_test.go#49-64) | ✅ |
| [TestRegexDetector_Phone](file:///c:/Program1/sysMon/internal/pii/regex_test.go#65-80) | ✅ |
| [TestRegexDetector_NoFalsePositiveOnPlainText](file:///c:/Program1/sysMon/internal/pii/regex_test.go#81-92) | ✅ |
| [TestRegexDetector_Timeout](file:///c:/Program1/sysMon/internal/pii/regex_test.go#93-100) (ReDoS safety) | ✅ |
| [TestTokenMap_StoreAndLookup](file:///c:/Program1/sysMon/internal/pii/tokenmap_test.go#7-29) | ✅ |
| [TestTokenMap_DeterministicToken](file:///c:/Program1/sysMon/internal/pii/tokenmap_test.go#30-45) | ✅ |
| [TestTokenMap_DifferentPIIDifferentTokens](file:///c:/Program1/sysMon/internal/pii/tokenmap_test.go#46-60) | ✅ |
| [TestTokenMap_CleanupReleasesMemory](file:///c:/Program1/sysMon/internal/pii/tokenmap_test.go#61-79) | ✅ |
| [TestTokenMap_InjectionPrevention](file:///c:/Program1/sysMon/internal/pii/tokenmap_test.go#80-97) | ✅ |
| [TestRedactAndRehydrate_RoundTrip](file:///c:/Program1/sysMon/internal/pii/redactor_test.go#10-56) | ✅ |
| [TestRedact_PreservesNonPIIText](file:///c:/Program1/sysMon/internal/pii/redactor_test.go#57-77) | ✅ |

### Round-Trip Proof

```
Original:  My email is john@acme.com and SSN is 123-45-6789
Redacted:  My email is __PII_email_226ee41b..._8d56eb13b1cc__ and SSN is __PII_ssn_15a76524..._2967463d__
Restored:  My email is john@acme.com and SSN is 123-45-6789  ✅ exact match
```

## How to Run

```bash
# Build
go build -o pii-gateway.exe ./cmd/gateway

# Run
go run ./cmd/gateway/ --config config.yaml

# Test
go test ./... -v

# Test with race detector
go test -race ./...
```

## External Dependencies Installed

| Package | Version |
|---|---|
| `github.com/go-chi/chi/v5` | v5.2.5 |
| `github.com/spf13/viper` | v1.21.0 |
| `github.com/prometheus/client_golang` | v1.23.2 |
| `github.com/sony/gobreaker` | v1.0.0 |
| `github.com/google/uuid` | v1.6.0 |
| `golang.org/x/time` | v0.15.0 |
