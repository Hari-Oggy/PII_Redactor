# PII Gateway v4 Enhancement — Task Tracker

## Phase 1 — Fix Critical Bugs
- [x] 1.1 Implement real HMAC verification in [tokenmap.go](file:///c:/Program1/sysMon/internal/pii/tokenmap.go)
- [x] 1.2 Update [rehydrator.go](file:///c:/Program1/sysMon/internal/pii/rehydrator.go) to use HMAC verification
- [x] 1.3 Wire streaming proxy into main handler + fix discarded redaction
- [x] 1.4 Read API keys from environment variables in [handler.go](file:///c:/Program1/sysMon/internal/proxy/handler.go)
- [x] 1.5 Implement JWT validation in [auth.go](file:///c:/Program1/sysMon/internal/middleware/auth.go)
- [x] 1.6 Fix ReDoS data race in [regex.go](file:///c:/Program1/sysMon/internal/pii/regex.go)

## Phase 2 — Wire Disconnected Components
- [x] 2.1 Wire audit logger into server and handler
- [x] 2.2 Wire HeaderScan middleware into chi chain
- [x] 2.3 Connect admin blocklist to PII engine
- [x] 2.4 Implement real config reload endpoint

## Phase 3 — Security Enhancements
- [x] 3.1 In-memory PII encryption
- [x] 3.2 Prompt injection detection
- [x] 3.3 Egress domain allowlist (SSRF prevention)
- [x] 3.4 Multipart file upload scanning

## Phase 4 — Operational Polish
- [x] 4.1 Structured logging with zap
- [x] 4.2 Move /metrics to admin port (done in Phase 2)
- [x] 4.3 Add Gemini provider config entry
- [x] 4.4 Create README.md
- [x] 4.5 Improve credit card regex

## Phase 5 — Testing & Benchmarks
- [x] 5.1 Integration test suite
- [x] 5.2 Fuzz testing
- [x] 5.3 Load benchmarks
- [x] 5.4 Expand existing test coverage

## Phase 6 — Future Architecture
- [ ] 6.1 NER ML sidecar
- [ ] 6.2 Redis token map
- [ ] 6.3 RBAC per department
- [ ] 6.4 WebSocket support
- [ ] 6.5 Policy engine
- [ ] 6.6 Dashboard UI
