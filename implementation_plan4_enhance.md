# PII Redactor Gateway — v4 Enhancement Plan

Deep code-level analysis of the current v3 implementation across all 37 source files. This document identifies **concrete flaws** in the existing code and proposes **future enhancements** grouped by priority.

---

## 0 · v3 Code-Level Flaws Found (24 issues)

> [!CAUTION]
> These are **real bugs and gaps** found by reading every source file — not theoretical concerns.

### 🔴 Critical (Must fix — Security / Correctness broken)

| # | Flaw | File | Evidence |
|---|---|---|---|
| 1 | **HMAC verification is a no-op** | [tokenmap.go](file:///c:/Program1/sysMon/internal/pii/tokenmap.go#L90-L100) | `VerifyAndLookup()` just does a map lookup — it never actually validates the HMAC signature against the UUID. A forged token that happens to be in the map passes. |
| 2 | **Rehydrator doesn't use HMAC verification** | [rehydrator.go](file:///c:/Program1/sysMon/internal/pii/rehydrator.go#L29-L36) | It iterates `tokenToPII` directly and does `strings.ReplaceAll`. The `VerifyAndLookup()` method is never called. Any token in the map is blindly accepted. |
| 3 | **Streaming proxy is dead code** | [streaming.go](file:///c:/Program1/sysMon/internal/proxy/streaming.go) | `StreamingProxy` is never instantiated or called from `handler.go` or `server.go`. SSE responses are handled as regular buffered responses, defeating the entire overlap-buffer design. |
| 4 | **Streaming redaction result is discarded** | [streaming.go:72-73](file:///c:/Program1/sysMon/internal/proxy/streaming.go#L72-L73) | `redacted, _ := sp.redactor.Redact(...)` → `_ = redacted`. The redacted text is thrown away and the original unredacted data is written to the client. |
| 5 | **API keys not read from env vars** | [handler.go:238-244](file:///c:/Program1/sysMon/internal/proxy/handler.go#L238-L244) | Code says `// In production, read from os.Getenv(...)` but just passes through the original `Authorization` header. The `api_key_env` config field is unused. |
| 6 | **JWT auth is a TODO stub** | [auth.go:37](file:///c:/Program1/sysMon/internal/middleware/auth.go#L37) | `// TODO: JWT validation using golang-jwt/jwt/v5`. No actual JWT parsing or signature verification exists. |

### 🟠 High (Functional gaps — features described in plan but not wired)

| # | Flaw | File | Evidence |
|---|---|---|---|
| 7 | **Audit logger never used** | [logger.go](file:///c:/Program1/sysMon/internal/audit/logger.go) | `audit.Logger` exists but is never instantiated in `server.go` or called from `handler.go`. No audit trail is written for any request. |
| 8 | **HeaderScan middleware not wired** | [headerscan.go](file:///c:/Program1/sysMon/internal/middleware/headerscan.go) | `HeaderScan()` requires a `tokenMap` function injected but is never added to the middleware chain in `server.go`. Headers and query params are not scanned. |
| 9 | **Admin blocklist is disconnected** | [admin/handler.go:93-95](file:///c:/Program1/sysMon/internal/admin/handler.go#L93-L95) | Blocklist CRUD modifies a local `[]string` on the admin handler, but the actual `BlocklistDetector` in the PII engine has its own separate copy. Updates via admin API have zero effect on scanning. |
| 10 | **Config reload endpoint is a no-op** | [admin/handler.go:110-128](file:///c:/Program1/sysMon/internal/admin/handler.go#L110-L128) | `/admin/config/reload` just reads the current config and returns it. It doesn't trigger Viper to re-read the file or force an atomic swap. |
| 11 | **ReDoS timeout is racy** | [regex.go:93-118](file:///c:/Program1/sysMon/internal/pii/regex.go#L93-L118) | The goroutine writes to the `matches` slice while the main goroutine may read it after timeout. This is a data race (would fail `go test -race`). |
| 12 | **Credit card regex is too greedy** | [regex.go:47](file:///c:/Program1/sysMon/internal/pii/regex.go#L47) | Pattern `\b(?:\d[ -]*?){13,19}\b` matches any 13+ digit sequence, including timestamps, IDs, and phone numbers — massive false positive rate. |

### 🟡 Medium (Missing features / Operational gaps)

| # | Flaw | File | Evidence |
|---|---|---|---|
| 13 | **No `test/` directory or integration tests** | Project root | Plans reference `test/integration/` and `test/benchmark/` but neither directory exists. |
| 14 | **No README.md** | Project root | Plans reference `README.md` but none exists. |
| 15 | **Gemini provider has no config entry** | [config.yaml](file:///c:/Program1/sysMon/config.yaml) | `gemini.go` adapter is registered but there's no provider entry in `config.yaml` for it, so it can never match a route. |
| 16 | **`go.mod` module path mismatch risk** | [go.mod](file:///c:/Program1/sysMon/go.mod) | Module is `github.com/enterprise/pii-gateway` but this is a local project. Imports may break if Go tries to fetch from GitHub. |
| 17 | **No structured logging** | [main.go](file:///c:/Program1/sysMon/cmd/gateway/main.go) | Uses `log.Printf` everywhere instead of `go.uber.org/zap` (which is in `go.mod`). No JSON-structured logs for SIEM/ELK ingestion. |
| 18 | **Metrics handler exposed on proxy port** | [server.go:81](file:///c:/Program1/sysMon/internal/server/server.go#L81) | `/metrics` is on `:8080` (public). Should be on admin port `:9090` only, or at least behind auth. |

---

## 1 · Proposed Enhancement Plan (v4)

### Phase 1 — Fix Critical Bugs (Priority: Immediate)

#### 1.1 Implement Real HMAC Verification

**Files:** `tokenmap.go`, `rehydrator.go`

- Parse the token format `__PII_{type}_{uuid}_{hmac}__`
- In `VerifyAndLookup()`, extract the UUID portion, recompute `HMAC-SHA256(uuid, requestSecret)`, and compare with the embedded HMAC
- Update `Rehydrator.Rehydrate()` to call `VerifyAndLookup()` instead of directly iterating the map
- **Impact:** Prevents token injection attacks — the core security promise of the gateway

#### 1.2 Wire Streaming Proxy into Main Handler

**Files:** `handler.go`, `server.go`

- Detect SSE responses via `Content-Type: text/event-stream` header in upstream response
- Route SSE responses through `StreamingProxy.ProxySSE()` instead of buffering
- Fix the discarded `redacted` variable in `streaming.go` so redacted text is actually emitted
- **Impact:** Without this, any streaming LLM response (which is the default for ChatGPT) bypasses PII scanning entirely

#### 1.3 Read API Keys from Environment Variables

**Files:** `handler.go`

- Replace the TODO comment with actual `os.Getenv(providerCfg.APIKeyEnv)`
- Set appropriate auth headers per provider (OpenAI uses `Bearer`, Anthropic uses `x-api-key`, Azure uses `api-key`)
- **Impact:** Gateway currently can't authenticate to any upstream LLM

#### 1.4 Implement JWT Validation

**Files:** `auth.go`

- Use `github.com/golang-jwt/jwt/v5` (already in `go.mod`)
- Support both symmetric (`jwt_secret`) and asymmetric (`jwt_public_key_file`) verification
- Extract `sub` claim for audit logging
- **Impact:** Authentication is completely bypassed when `auth.enabled = true` and no static API key matches

#### 1.5 Fix ReDoS Data Race

**Files:** `regex.go`

- Use a channel to return matches from the goroutine instead of shared slice mutation
- Or use `sync.Mutex` to guard the `matches` slice
- **Impact:** Will cause panics or corrupted data under concurrent load

---

### Phase 2 — Wire Disconnected Components (Priority: High)

#### 2.1 Wire Audit Logger

**Files:** `server.go`, `handler.go`

- Instantiate `audit.NewLogger()` in `server.New()`
- Call `logger.Log()` at the end of each proxied request in `handler.go`
- Include `X-Request-ID`, user ID, provider, PII count, latency, status code

#### 2.2 Wire HeaderScan Middleware

**Files:** `server.go`

- Add `middleware.HeaderScan(pipeline, redactor, tokenMapFn)` to the chi middleware chain
- Requires solving the chicken-and-egg problem: `HeaderScan` needs a `TokenMap`, but the `TokenMap` is currently created inside `handler.ServeHTTP()`
- Solution: Create `TokenMap` in a middleware and store it in request context

#### 2.3 Connect Admin Blocklist to PII Engine

**Files:** `admin/handler.go`, `pii/blocklist.go`

- Give admin handler a reference to the live `BlocklistDetector`
- When admin adds/removes terms, update the detector's internal list atomically
- Or: Store blocklist in the `Config` struct and reload atomically

#### 2.4 Implement Real Config Reload Endpoint

**Files:** `admin/handler.go`, `config/config.go`

- Expose a `Reload(path)` function in the config package
- `/admin/config/reload` POST should trigger a re-read + re-parse + atomic swap

---

### Phase 3 — New Security Enhancements (Priority: Medium-High)

#### 3.1 In-Memory PII Encryption

Encrypt PII values stored in the `TokenMap` using AES-GCM with a per-process key. If an attacker dumps the Go heap, they get ciphertext instead of plaintext PII.

#### 3.2 Prompt Injection Detection

Add a middleware that classifies requests for prompt injection patterns (e.g., "ignore previous instructions", "you are now DAN"). Block or flag these before they reach the LLM.

#### 3.3 Egress Domain Allowlist (SSRF Prevention)

Add a custom `http.Transport` with a `DialContext` that resolves the upstream DNS and rejects connections to private IPs (`10.x`, `192.168.x`, `127.x`). Only allow configured provider domains.

#### 3.4 Sensitive File Upload Scanning

Parse `multipart/form-data` requests. Decode base64 file attachments and run PII detection on the decoded content before forwarding.

---

### Phase 4 — Operational Enhancements (Priority: Medium)

#### 4.1 Structured Logging with Zap

Replace all `log.Printf` calls with `go.uber.org/zap` structured JSON logging. Include `X-Request-ID` in every log line automatically.

#### 4.2 Move `/metrics` to Admin Port

Remove the metrics handler from the proxy router and register it only on the admin server (`:9090`).

#### 4.3 Add Gemini Provider Config Entry

Add a `gemini` provider block to `config.yaml` with the correct `base_url` and path prefix.

#### 4.4 Create README.md

Write a comprehensive README covering: project overview, architecture diagram, quick start guide, configuration reference, provider setup, and development instructions.

#### 4.5 Improve Credit Card Regex

Replace the greedy pattern with Luhn-algorithm validation. After regex match, run Luhn checksum — only flag as PII if checksum passes.

---

### Phase 5 — Testing & Benchmarks (Priority: Medium)

#### 5.1 Integration Test Suite

Create `test/integration/proxy_integration_test.go`:
- Spin up a mock LLM HTTP server
- Boot the gateway pointing at the mock
- Send requests with known PII, assert PII is stripped before reaching mock
- Assert re-hydration works in responses

#### 5.2 Fuzz Testing

Add `go test -fuzz` targets for:
- Overlap buffer with random chunked input
- Regex detector with adversarial payloads
- Token map with concurrent access patterns

#### 5.3 Load Benchmarks

Create `test/benchmark/`:
- `pii_bench_test.go` — micro-benchmarks for the PII engine
- `loadtest.js` — k6 script for sustained throughput testing

#### 5.4 Fix Existing Test Coverage

- `redactor_test.go`, `regex_test.go`, `tokenmap_test.go` exist but need to be expanded
- Add tests for the `rehydrator`, `allowlist`, `confidence`, `overlap`, `blocklist` packages — none currently have tests

---

### Phase 6 — Future Architecture (Priority: Low — Long-Term)

| Enhancement | Description |
|---|---|
| **NER ML Sidecar** | Deploy a Python gRPC service running Microsoft Presidio or spaCy for contextual PII detection (names, addresses) |
| **Redis Token Map** | Move token storage to Redis with TTL for cross-instance resilience and zero-downtime deploys |
| **RBAC per Department** | Tie PII rules to SSO groups — HR sees names, Engineering doesn't |
| **WebSocket Support** | Proxy WebSocket connections (used by some LLM providers for real-time streaming) |
| **Policy Engine** | Configurable rules like "block requests with > 5 PII items" or "allow SSN only for Finance team" |
| **Dashboard UI** | Web-based admin dashboard showing real-time PII detection metrics, audit logs, and provider health |

---

## 2 · Summary Table

| Phase | Items | Effort | Priority |
|---|---|---|---|
| **Phase 1** — Fix Critical Bugs | 5 items | ~3 days | 🔴 Immediate |
| **Phase 2** — Wire Disconnected Parts | 4 items | ~2 days | 🟠 High |
| **Phase 3** — Security Enhancements | 4 items | ~4 days | 🟠 Medium-High |
| **Phase 4** — Operational Polish | 5 items | ~2 days | 🟡 Medium |
| **Phase 5** — Testing & Benchmarks | 4 items | ~3 days | 🟡 Medium |
| **Phase 6** — Architecture Evolution | 6 items | ~Weeks | 🔵 Long-term |
