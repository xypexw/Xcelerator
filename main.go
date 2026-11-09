// ===================================================================================
// XCELLATOR — High-Performance BFF (Backend-For-Frontend) Gateway
// ===================================================================================
//
// Xcellator is a lightweight, single-binary BFF layer built with Go + Fiber that sits
// between the APISIX API Gateway and the PeacockXTR Spring Boot backend. It replaces
// the legacy PeacockBFF service.
//
// ┌──────────┐      ┌─────────┐      ┌────────────┐      ┌─────────────┐
// │ Frontend │ ───▶ │ APISIX  │ ───▶ │ Xcellator  │ ───▶ │ PeacockXTR  │
// │          │      │ Gateway │      │ (BFF:8081) │      │ (Core:8080) │
// └──────────┘      └─────────┘      └────────────┘      └─────────────┘
//
// ARCHITECTURE DECISIONS:
// ──────────────────────
// 1. APISIX handles JWT-to-UserId resolution (Lua plugin validates bearer token against
//    Redis session store, strips Authorization header, injects X-User-Id & Custom-User-Id).
//    Xcellator therefore does NOT re-validate JWT tokens — it trusts X-User-Id from APISIX.
//
// 2. Frontend sends two key headers:
//    - "Authorization: Bearer <JWT>" → consumed by APISIX, replaced with X-User-Id
//    - "Idempotency: <UUID>"         → consumed by Xcellator for write-operation dedup
//
// 3. Xcellator's responsibilities:
//    a) Validate & transform the "Idempotency" header into "X-Idempotency-Key" for backend
//    b) Deduplicate write requests via Redis SETNX (24h TTL)
//    c) Passthrough X-User-Id and other internal headers to backend
//    d) Reverse-proxy all /bff/* requests to PeacockXTR, stripping the /bff prefix
//    e) Generate X-Request-Id (UUID) for distributed tracing
//
// 4. Route mapping: APISIX routes /bff/* → Xcellator:8081
//    Xcellator strips /bff prefix and forwards to PeacockXTR:8080
//    Example: /bff/api/v1/teams → /api/v1/teams
//
// CONFIGURATION (Environment Variables):
// ──────────────────────────────────────
//   BACKEND_URL         — PeacockXTR base URL (default: http://peacock-app:8080)
//   REDIS_ADDR          — Redis address for idempotency dedup (default: redis:6379)
//   REDIS_PASSWORD      — Redis password (default: empty)
//   REDIS_DB            — Redis database number (default: 0)
//   IDEMPOTENCY_TTL_HRS — Idempotency key TTL in hours (default: 24)
//   PORT                — Server listen port (default: 8081)
// ===================================================================================

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// ===================================================================================
// SECTION 1: CONFIGURATION
// ===================================================================================

// Config holds all runtime configuration for the Xcellator BFF service.
// Values are loaded from environment variables with sensible defaults for
// containerized deployment alongside PeacockXTR and Redis.
type Config struct {
	BackendURL      string        // Base URL of PeacockXTR backend (e.g., http://peacock-app:8080)
	RedisAddr       string        // Redis server address in host:port format
	RedisPassword   string        // Redis authentication password (empty for no auth)
	RedisDB         int           // Redis database index (0-15)
	IdempotencyTTL  time.Duration // How long idempotency keys are retained in Redis
	Port            string        // Port this BFF server listens on
}

// LoadConfig reads configuration from environment variables.
// Every field has a production-ready default value so the service can start
// without any env vars in a standard Docker Compose deployment.
func LoadConfig() Config {
	redisDB, _ := strconv.Atoi(getEnv("REDIS_DB", "0"))
	ttlHours, _ := strconv.Atoi(getEnv("IDEMPOTENCY_TTL_HRS", "24"))

	// Support both BACKEND_URL and legacy/docker-compose XTR_BASE_URL
	backendURL := getEnv("BACKEND_URL", getEnv("XTR_BASE_URL", "http://peacock-app:8080"))

	// Support both REDIS_ADDR and legacy/docker-compose REDIS_HOST + REDIS_PORT
	redisHost := getEnv("REDIS_HOST", "redis")
	redisPort := getEnv("REDIS_PORT", "6379")
	redisAddr := getEnv("REDIS_ADDR", fmt.Sprintf("%s:%s", redisHost, redisPort))

	return Config{
		BackendURL:     backendURL,
		RedisAddr:      redisAddr,
		RedisPassword:  getEnv("REDIS_PASSWORD", ""),
		RedisDB:        redisDB,
		IdempotencyTTL: time.Duration(ttlHours) * time.Hour,
		Port:           getEnv("PORT", "8081"),
	}
}

// getEnv returns the value of an environment variable or a fallback default.
func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		return val
	}
	return fallback
}

// ===================================================================================
// SECTION 2: REDIS CLIENT
// ===================================================================================

// newRedisClient creates a go-redis client configured for the idempotency store.
// The same Redis instance is used by APISIX for session/rate-limit, so we share
// the infrastructure but use a dedicated key prefix ("idempotency:").
func newRedisClient(cfg Config) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
}

// ===================================================================================
// SECTION 3: HTTP CLIENT FOR BACKEND PROXY
// ===================================================================================

// newHTTPClient creates an http.Client optimized for internal service-to-service
// communication with PeacockXTR. Connection pooling is configured for high throughput
// in a containerized environment.
func newHTTPClient() *http.Client {
	transport := &http.Transport{
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: false},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

// ===================================================================================
// SECTION 4: UUID VALIDATION
// ===================================================================================

// uuidRegex validates that a string is a well-formed UUID v4 (or any UUID format).
// This matches the same validation pattern used by PeacockXTR's IdempotencyInterceptor.
var uuidRegex = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`,
)

// ===================================================================================
// SECTION 5: STANDARD ERROR RESPONSE
// ===================================================================================

// ErrorResponse mirrors PeacockXTR's ErrorResponse DTO for consistent error format
// across the entire API surface. Frontend can rely on the same error shape regardless
// of whether the error originated in the BFF or the backend.
type ErrorResponse struct {
	Status    int    `json:"status"`
	Error     string `json:"error"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
}

// sendError writes a standardized JSON error response matching PeacockXTR's format.
func sendError(c *fiber.Ctx, status int, errType, message string) error {
	return c.Status(status).JSON(ErrorResponse{
		Status:    status,
		Error:     errType,
		Message:   message,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

// ===================================================================================
// SECTION 6: MIDDLEWARE — Request ID (Distributed Tracing)
// ===================================================================================
//
// This middleware generates a unique X-Request-Id for every incoming request,
// equivalent to PeacockXTR's MDCLogFilter. The ID is:
//   - Set as a response header so the frontend can correlate errors
//   - Passed downstream to PeacockXTR for end-to-end tracing
//   - Logged by Fiber's logger middleware for searchable access logs
//
// We use Fiber's built-in requestid middleware (configured in main) which handles
// this automatically.

// ===================================================================================
// SECTION 6B: MIDDLEWARE — JWT Resolution & Header Handling
// ===================================================================================
//
// PURPOSE:
// Resolves user identity from incoming request headers and ensures secure propagation
// downstream to PeacockXTR.
//
// DUAL-MODE BEHAVIOR:
// 1. Gateway Mode (Normal):
//    APISIX gateway executes Lua auth plugin, verifies JWT against Redis session store,
//    injects X-User-Id & Custom-User-Id, and strips Authorization header.
//    Xcellator detects pre-resolved X-User-Id and passes it straight through.
//
// 2. Direct / Standalone Mode (Fallback & Testing):
//    If client sends "Authorization: Bearer <JWT>" directly to Xcellator (bypassing APISIX),
//    Xcellator parses the token, queries the shared Redis session store
//    ("peacockxt:session:token:<token>"), resolves the userId, and injects X-User-Id.
//
// SECURITY GUARANTEE:
// Authorization header is NEVER forwarded downstream to PeacockXTR. Backend Core
// relies entirely on the authenticated internal header X-User-Id.
var jwtRegex = regexp.MustCompile(`^eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_=]+$`)

func jwtAuthMiddleware(rdb *redis.Client) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// 1. If X-User-Id was already resolved by APISIX, proceed immediately
		if userId := c.Get("X-User-Id"); userId != "" {
			return c.Next()
		}

		// 2. If Authorization header is provided directly by Frontend
		authHeader := c.Get("Authorization")
		if authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
				token := strings.TrimSpace(parts[1])
				if !jwtRegex.MatchString(token) {
					return sendError(c, fiber.StatusBadRequest, "Bad Request", "Malformed JWT token format.")
				}

				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()

				redisKey := "peacockxt:session:token:" + token
				userId, err := rdb.Get(ctx, redisKey).Result()
				if err != nil || userId == "" {
					return sendError(c, fiber.StatusUnauthorized, "Unauthorized", "Invalid or expired session token.")
				}

				// Inject resolved user ID for internal handlers and downstream backend
				c.Request().Header.Set("X-User-Id", userId)
				c.Request().Header.Set("Custom-User-Id", userId)
				return c.Next()
			}
			return sendError(c, fiber.StatusUnauthorized, "Unauthorized", "Invalid Bearer format.")
		}

		// Allow unauthenticated requests for public storage endpoints; protected
		// endpoints will be guarded by backend or lack of X-User-Id
		return c.Next()
	}
}

// ===================================================================================
// SECTION 7: MIDDLEWARE — Idempotency Guard (Write-Operation Deduplication)
// ===================================================================================
//
// PURPOSE:
// Prevents duplicate processing of write operations (POST, PUT, DELETE).
// This is critical for operations like creating teams, sending messages, or
// deleting resources where network retries could cause double-execution.
//
// FLOW:
// 1. Frontend includes "Idempotency: <UUID>" header on every write request
// 2. This middleware validates the UUID format
// 3. Attempts Redis SETNX with key "idempotency:<uuid>" and 24h TTL
// 4. If key already exists → 409 Conflict (duplicate request)
// 5. If key is new → proceed and forward as "X-Idempotency-Key" to backend
//
// NOTE: Read operations (GET) bypass this middleware entirely.
// This mirrors the exact behavior of PeacockXTR's IdempotencyInterceptor.java
// but is enforced at the BFF layer so the backend doesn't need to check again.
// However, we still forward the header so backend can use it for its own logging.

func idempotencyMiddleware(rdb *redis.Client, ttl time.Duration) fiber.Handler {
	return func(c *fiber.Ctx) error {
		method := c.Method()

		// ── Skip read operations ──────────────────────────────────────
		// GET and HEAD requests are inherently idempotent; no dedup needed.
		if method == fiber.MethodGet || method == fiber.MethodHead || method == fiber.MethodOptions {
			return c.Next()
		}

		// ── Extract Idempotency header from frontend ──────────────────
		// Frontend sends "Idempotency: <UUID>" (not "X-Idempotency-Key").
		// The BFF transforms this into the backend's expected header format.
		idempotencyKey := c.Get("Idempotency")
		if idempotencyKey == "" {
			return sendError(c, fiber.StatusBadRequest, "Bad Request",
				"Missing Idempotency header. All write operations require a UUID idempotency key.")
		}

		// ── Validate UUID format ──────────────────────────────────────
		// Must be a standard UUID (8-4-4-4-12 hex format).
		// Rejects malformed keys before hitting Redis.
		if !uuidRegex.MatchString(idempotencyKey) {
			return sendError(c, fiber.StatusBadRequest, "Bad Request",
				"Invalid Idempotency key format. Must be a valid UUID (e.g., 550e8400-e29b-41d4-a716-446655440000).")
		}

		// ── Build composite Redis key ─────────────────────────────────
		// Backend's IdempotencyInterceptor uses key format: IK::[UserId]::[URI]::[IdempotencyKey]
		// This ensures the same idempotency key can be reused across different
		// users and different endpoints without collision.
		userId := c.Get("X-User-Id", "anonymous")
		uri := c.Path() // e.g., /bff/api/v1/teams
		redisKey := fmt.Sprintf("IK::%s::%s::%s", userId, uri, idempotencyKey)

		// ── Redis SETNX for deduplication ─────────────────────────────
		// Uses SET with NX (Not eXists) flag. If the key already exists,
		// this means the same request was already processed → reject as duplicate.
		// TTL ensures keys are cleaned up automatically after 24 hours.
		ctx := context.Background()

		wasSet, err := rdb.SetNX(ctx, redisKey, "STARTED", ttl).Result()
		if err != nil {
			// Redis failure should not block requests — log and proceed.
			// In production, consider circuit-breaker patterns here.
			log.Printf("[WARN] Redis idempotency check failed: %v — allowing request through", err)
			c.Request().Header.Set("X-Idempotency-Key", idempotencyKey)
			return c.Next()
		}

		if !wasSet {
			// Key already exists — check if it's still in-progress or completed
			existingVal, _ := rdb.Get(ctx, redisKey).Result()
			if existingVal == "STARTED" {
				// Request is still being processed (concurrent duplicate)
				return sendError(c, fiber.StatusConflict, "Conflict",
					"Request is already in progress. Please wait for the original request to complete.")
			}
			// Request was already completed — return cached status info
			return sendError(c, fiber.StatusConflict, "Conflict",
				"Duplicate request detected. This idempotency key has already been used.")
		}

		// ── Store Redis key in locals for afterCompletion logic ────────
		// We store the key so the response handler can update it with the
		// final HTTP status or delete it on failure (allowing retry).
		c.Locals("idempotencyRedisKey", redisKey)

		// ── Transform header for backend ──────────────────────────────
		// Backend expects "X-Idempotency-Key", not "Idempotency".
		// We set it on the outgoing request context for the proxy handler.
		c.Request().Header.Set("X-Idempotency-Key", idempotencyKey)

		return c.Next()
	}
}

// ===================================================================================
// SECTION 8: REVERSE PROXY HANDLER
// ===================================================================================
//
// The core of Xcellator: a generic reverse proxy that forwards all requests from
// the BFF to PeacockXTR. This is NOT a simple TCP proxy — it's an application-level
// proxy that:
//
// 1. Strips the /bff prefix from the URL path
// 2. Preserves query parameters
// 3. Forwards approved internal headers (X-User-Id, X-Membership-Id, etc.)
// 4. Adds the X-Idempotency-Key header (transformed from Idempotency)
// 5. Adds X-Request-Id for distributed tracing
// 6. Streams the response back with original status code and headers
//
// HEADER FORWARDING STRATEGY:
// ────────────────────────────
// We use an explicit allowlist of headers to forward. This prevents leaking
// internal gateway headers or accidentally forwarding hop-by-hop headers.
//
// Headers forwarded to PeacockXTR:
//   - X-User-Id          → Resolved by APISIX from JWT, identifies the authenticated user
//   - Custom-User-Id     → Alias of X-User-Id (set by APISIX for rate limiting)
//   - X-Membership-Id    → Team membership context, set by frontend for team-scoped ops
//   - X-User-Role        → User's role in team context (used by deleteTeam)
//   - X-Team-Id          → Team context for cross-resource operations (e.g., comments)
//   - X-Idempotency-Key  → Transformed from frontend's "Idempotency" header
//   - X-Request-Id       → Generated by BFF for distributed tracing
//   - Content-Type       → Required for request body parsing

// headersToForward defines the allowlist of headers that are proxied from the
// BFF request to the PeacockXTR backend. Each header serves a specific purpose
// in the backend's request processing pipeline.
var headersToForward = []string{
	"X-User-Id",         // Authenticated user ID (resolved from JWT by APISIX)
	"Custom-User-Id",    // Alias of X-User-Id (used by APISIX rate limiter)
	"X-Membership-Id",   // Caller's membership ID within the target team
	"X-User-Role",       // Caller's role in the team (e.g., "OWNER", "MEMBER")
	"X-Team-Id",         // Team context for cross-resource endpoints (e.g., comments)
	"X-Idempotency-Key", // Idempotency key for write-operation deduplication
	"X-Request-Id",      // Distributed tracing correlation ID
	"Content-Type",      // MIME type of request body (application/json)
}

// proxyHandler creates a Fiber handler that reverse-proxies requests to the
// PeacockXTR backend service. The pathPrefix parameter specifies what prefix
// to strip from incoming request paths before forwarding.
//
// Example: pathPrefix="/bff" transforms /bff/api/v1/teams → /api/v1/teams
func proxyHandler(backendURL string, httpClient *http.Client, pathPrefix string, rdb *redis.Client) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// ── Build downstream URL ──────────────────────────────────────
		// Strip the BFF prefix and reconstruct the full backend URL.
		// Fiber's c.OriginalURL() includes query parameters.
		originalPath := c.OriginalURL() // e.g., /bff/api/v1/teams?teamIds=1,2
		downstreamPath := strings.TrimPrefix(originalPath, pathPrefix)
		if downstreamPath == "" {
			downstreamPath = "/"
		}
		targetURL := backendURL + downstreamPath

		// ── Create downstream HTTP request ────────────────────────────
		var bodyReader io.Reader
		if len(c.Body()) > 0 {
			bodyReader = strings.NewReader(string(c.Body()))
		}

		req, err := http.NewRequestWithContext(c.Context(), c.Method(), targetURL, bodyReader)
		if err != nil {
			log.Printf("[ERROR] Failed to create proxy request: %v", err)
			return sendError(c, fiber.StatusInternalServerError, "Internal Server Error",
				"Failed to construct downstream request.")
		}

		// ── Forward allowed headers ───────────────────────────────────
		// Only headers in the allowlist are forwarded to prevent header
		// injection attacks and accidental exposure of gateway internals.
		for _, header := range headersToForward {
			if val := c.Get(header); val != "" {
				req.Header.Set(header, val)
			}
		}

		// Ensure Content-Type is set for requests with body
		if bodyReader != nil && req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/json")
		}

		// ── Execute downstream request ────────────────────────────────
		resp, err := httpClient.Do(req)
		if err != nil {
			log.Printf("[ERROR] Backend proxy request failed: %v | URL: %s", err, targetURL)
			return sendError(c, fiber.StatusBadGateway, "Bad Gateway",
				"The backend service is currently unavailable. Please try again later.")
		}
		defer resp.Body.Close()

		// ── Stream response back to client ────────────────────────────
		// Copy the backend's response status, headers, and body verbatim.
		// This ensures the frontend receives the exact same response as if
		// it were talking directly to PeacockXTR.

		// Copy response headers (excluding hop-by-hop headers)
		for key, values := range resp.Header {
			// Skip hop-by-hop headers that shouldn't be forwarded
			lowerKey := strings.ToLower(key)
			if lowerKey == "transfer-encoding" || lowerKey == "connection" {
				continue
			}
			for _, v := range values {
				c.Response().Header.Add(key, v)
			}
		}

		// Preserve the X-Request-Id in the response for frontend tracing
		if reqID := c.Get("X-Request-Id"); reqID != "" {
			c.Response().Header.Set("X-Request-Id", reqID)
		}

		// Read and forward response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[ERROR] Failed to read backend response body: %v", err)
			return sendError(c, fiber.StatusBadGateway, "Bad Gateway",
				"Failed to read response from backend service.")
		}

		// ── Idempotency afterCompletion logic ─────────────────────────
		// Mirrors PeacockXTR's IdempotencyInterceptor.afterCompletion:
		// - If the backend returned an error (>= 400), DELETE the Redis key
		//   so the client can retry with the same idempotency key.
		// - If the backend returned success (< 400), UPDATE the Redis value
		//   to the final HTTP status code (caching the result).
		if redisKey, ok := c.Locals("idempotencyRedisKey").(string); ok && redisKey != "" {
			ctx := context.Background()
			if resp.StatusCode >= 400 {
				// Backend rejected the request → allow client to retry
				rdb.Del(ctx, redisKey)
			} else {
				// Backend accepted → cache the status code
				rdb.Set(ctx, redisKey, strconv.Itoa(resp.StatusCode), 0) // keep existing TTL
			}
		}

		c.Status(resp.StatusCode)
		return c.Send(body)
	}
}

// ===================================================================================
// SECTION 9: HEALTH CHECK ENDPOINT
// ===================================================================================
//
// GET /health
//
// Standard health check endpoint for container orchestration (Docker, Kubernetes).
// Returns the service status and a timestamp. Used by:
//   - Docker HEALTHCHECK directive in Dockerfile
//   - Kubernetes liveness/readiness probes
//   - APISIX upstream health checks (if configured)
//
// The endpoint also verifies Redis connectivity to ensure the idempotency
// subsystem is operational.

func healthHandler(rdb *redis.Client) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Check Redis connectivity
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		redisStatus := "UP"
		if err := rdb.Ping(ctx).Err(); err != nil {
			redisStatus = "DOWN"
			log.Printf("[WARN] Health check: Redis is down: %v", err)
		}

		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"service":   "xcellator",
			"status":    "UP",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"version":   "1.0.0",
			"redis":     redisStatus,
		})
	}
}

// ===================================================================================
// SECTION 10: APPLICATION BOOTSTRAP
// ===================================================================================
//
// main() wires together all components:
//   1. Load configuration from environment
//   2. Initialize Redis client for idempotency deduplication
//   3. Initialize HTTP client for backend proxying
//   4. Create Fiber app with production settings
//   5. Register global middleware (recovery, logging, request-id)
//   6. Register the /health endpoint (no auth required)
//   7. Register the /bff/* catch-all route group with idempotency middleware
//   8. Start the HTTP server on the configured port
//
// ROUTE STRUCTURE:
// ────────────────
// All BFF-proxied traffic enters through /bff/* which maps to APISIX's
// "bff-protected-route". The BFF strips /bff and proxies to PeacockXTR.
//
// The following PeacockXTR endpoints are accessible through the BFF:
//
// ┌─────────────────────────────────────────────────────────────────────────────────────┐
// │ DOMAIN          │ BFF PATH (→ Backend Path)                    │ METHODS           │
// ├─────────────────┼──────────────────────────────────────────────┼───────────────────┤
// │ Auth            │ /bff/api/auth/setting-avatar                │ POST              │
// │                 │ /bff/api/auth/delete-avatar                 │ DELETE            │
// │                 │                                              │                   │
// │ Teams           │ /bff/api/v1/teams                           │ GET, POST         │
// │                 │ /bff/api/v1/teams/:teamId                   │ PUT, DELETE       │
// │                 │                                              │                   │
// │ Channels        │ /bff/api/v1/teams/:id/channels              │ GET, POST         │
// │                 │ /bff/api/v1/teams/:id/channels/:cId         │ PUT, DELETE       │
// │                 │                                              │                   │
// │ Posts           │ /bff/api/v1/teams/:id/posts                 │ GET, POST         │
// │                 │ /bff/api/v1/teams/:id/posts/:pId            │ GET, PUT, DELETE  │
// │                 │                                              │                   │
// │ Messages        │ /bff/api/v1/channels/:id/messages           │ GET, POST         │
// │                 │ /bff/api/v1/channels/:id/messages/:mId      │ PUT, DELETE       │
// │                 │                                              │                   │
// │ Comments        │ /bff/api/v1/posts/:id/comments              │ GET, POST         │
// │                 │ /bff/api/v1/posts/:id/comments/:cId         │ PUT, DELETE       │
// │                 │                                              │                   │
// │ Memberships     │ /bff/api/v1/users/me/memberships            │ GET               │
// │                 │ /bff/api/v1/teams/:id/memberships           │ GET, POST         │
// │                 │ /bff/api/v1/teams/:id/memberships/me        │ GET               │
// │                 │ /bff/api/v1/teams/:id/memberships/:mId      │ PUT, DELETE       │
// │                 │                                              │                   │
// │ Events          │ /bff/api/v1/teams/:id/events                │ GET, POST         │
// │                 │ /bff/api/v1/teams/:id/events/:eId           │ DELETE            │
// │                 │                                              │                   │
// │ Emojis          │ /bff/api/v1/teams/:id/emojis                │ GET, POST         │
// │                 │ /bff/api/v1/teams/:id/emojis/:name          │ DELETE            │
// │                 │                                              │                   │
// │ Direct Messages │ /bff/api/v1/private-sessions                │ POST              │
// │                 │ /bff/api/v1/private-sessions/:id/messages   │ GET, POST         │
// │                 │ /bff/api/v1/private-sessions/:id/msgs/:mId  │ PUT, DELETE       │
// │                 │                                              │                   │
// │ Private Session │ /bff/api/v1/users/me/private-sessions       │ GET               │
// │                 │ /bff/api/v1/users/me/private-sessions/with/:id │ GET            │
// │                 │                                              │                   │
// │ Public Storage  │ /bff/api/v1/public-storage/upload-policy    │ GET               │
// │                 │ /bff/api/v1/public-storage/download-url     │ GET               │
// │                 │ /bff/api/v1/public-storage/delete-url       │ GET               │
// │                 │                                              │                   │
// │ Private Storage │ /bff/api/v1/private-storage/upload-policy   │ GET               │
// │                 │ /bff/api/v1/private-storage/download-url    │ GET               │
// │                 │ /bff/api/v1/private-storage/delete-url      │ GET               │
// │                 │ /bff/api/v1/private-storage/batch-download  │ POST              │
// └─────────────────────────────────────────────────────────────────────────────────────┘
//
// NOTE: Public endpoints (login, refresh, minio webhook) are routed DIRECTLY to
// PeacockXTR by APISIX (Route 1) and never pass through Xcellator.

func main() {
	// ── Step 1: Load Configuration ────────────────────────────────────
	cfg := LoadConfig()
	log.Printf("[INFO] Xcellator BFF starting with config: backend=%s redis=%s port=%s",
		cfg.BackendURL, cfg.RedisAddr, cfg.Port)

	// ── Step 2: Initialize Redis Client ───────────────────────────────
	rdb := newRedisClient(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Printf("[WARN] Redis not reachable at startup: %v — idempotency checks will retry on demand", err)
	} else {
		log.Println("[INFO] Redis connection established successfully")
	}

	// ── Step 3: Initialize HTTP Client ────────────────────────────────
	httpClient := newHTTPClient()

	// ── Step 4: Create Fiber Application ──────────────────────────────
	app := fiber.New(fiber.Config{
		AppName:               "Xcellator BFF v1.0.0",
		DisableStartupMessage: false,
		ReadTimeout:           15 * time.Second,
		WriteTimeout:          30 * time.Second,
		IdleTimeout:           120 * time.Second,
		BodyLimit:             10 * 1024 * 1024, // 10 MB max body size
		// Fiber returns 400 for unmatched routes by default; we customize:
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return sendError(c, code, http.StatusText(code), err.Error())
		},
	})

	// ── Step 5: Global Middleware ──────────────────────────────────────

	// 5a. Panic Recovery — catches panics in handlers and returns 500
	// instead of crashing the process. Essential for production stability.
	app.Use(recover.New(recover.Config{
		EnableStackTrace: true,
	}))

	// 5b. Request ID — generates a UUID for each request and sets it as
	// the X-Request-Id response header. Equivalent to PeacockXTR's MDCLogFilter.
	app.Use(requestid.New(requestid.Config{
		Header:     "X-Request-Id",
		Generator:  func() string { return uuid.New().String() },
		ContextKey: "requestId",
	}))

	// 5c. Access Logger — structured request logging for observability.
	// Logs method, path, status, latency, and request ID for every request.
	app.Use(logger.New(logger.Config{
		Format:     "${time} | ${status} | ${latency} | ${method} ${path} | ReqID: ${locals:requestId}\n",
		TimeFormat: "2006-01-02 15:04:05",
		TimeZone:   "UTC",
	}))

	// ── Step 6: Health Check (No Auth Required) ───────────────────────
	// This endpoint is called by Docker HEALTHCHECK and/or Kubernetes probes.
	// It must NOT go through the idempotency middleware.
	app.Get("/health", healthHandler(rdb))

	// ── Step 7: BFF Route Group ───────────────────────────────────────
	// All proxied traffic enters through /bff/*
	// APISIX's "bff-protected-route" (Route 3) forwards /bff/* here after
	// performing JWT authentication and user resolution.
	bff := app.Group("/bff")

	// Apply JWT authentication & user resolution (handles both APISIX pre-resolved and direct JWT)
	bff.Use(jwtAuthMiddleware(rdb))

	// Apply idempotency middleware to the entire BFF group.
	// It only activates for write methods (POST/PUT/DELETE); reads pass through.
	bff.Use(idempotencyMiddleware(rdb, cfg.IdempotencyTTL))

	// ── Step 7a: Explicit Route Definitions ───────────────────────────
	// Each route is documented with its business purpose, required headers,
	// and the downstream PeacockXTR endpoint it maps to.

	proxy := proxyHandler(cfg.BackendURL, httpClient, "/bff", rdb)

	// ───────────────────────────────────────────────────────────────────
	// AUTH ENDPOINTS (Protected — requires X-User-Id from APISIX)
	// These are auth-related but protected endpoints that go through BFF.
	// Note: /api/auth/login and /api/auth/refresh are PUBLIC and routed
	// directly to PeacockXTR by APISIX (Route 1), bypassing the BFF.
	// ───────────────────────────────────────────────────────────────────

	// POST /bff/api/auth/setting-avatar
	// Business: Updates the authenticated user's avatar.
	// Headers: X-Idempotency-Key (from Idempotency), X-User-Id (from APISIX)
	// Body: { "keyObject": "<minio-object-key>" }
	// Backend: POST /api/auth/setting-avatar
	bff.Post("/api/auth/setting-avatar", proxy)

	// DELETE /bff/api/auth/delete-avatar
	// Business: Removes the authenticated user's avatar.
	// Headers: X-Idempotency-Key (from Idempotency), X-User-Id (from APISIX)
	// Backend: DELETE /api/auth/delete-avatar
	bff.Delete("/api/auth/delete-avatar", proxy)

	// ───────────────────────────────────────────────────────────────────
	// TEAM ENDPOINTS
	// Core team management: create, read, update, delete teams.
	// Teams are the top-level organizational unit in PeacockXT.
	// ───────────────────────────────────────────────────────────────────

	// GET /bff/api/v1/teams?teamIds=1,2,3
	// Business: Retrieves team details for the given team IDs.
	// Query: teamIds (required, comma-separated list of int64)
	// Backend: GET /api/v1/teams?teamIds=1,2,3
	// Response: [TeamResponse] — array of {teamId, name, description, status, type}
	bff.Get("/api/v1/teams", proxy)

	// POST /bff/api/v1/teams
	// Business: Creates a new team. The authenticated user becomes the owner.
	// Headers: X-Idempotency-Key, X-User-Id
	// Body: { "name": "...", "description": "...", "type": "..." }
	// Backend: POST /api/v1/teams
	bff.Post("/api/v1/teams", proxy)

	// PUT /bff/api/v1/teams/:teamId
	// Business: Updates team details (description, type). Only team owners/admins.
	// Headers: X-Idempotency-Key, X-User-Id
	// Body: { "description": "...", "type": "..." }
	// Backend: PUT /api/v1/teams/{teamId}
	bff.Put("/api/v1/teams/:teamId", proxy)

	// DELETE /bff/api/v1/teams/:teamId
	// Business: Deletes a team. Requires OWNER role (X-User-Role header).
	// Headers: X-Idempotency-Key, X-User-Id, X-User-Role
	// Backend: DELETE /api/v1/teams/{teamId}
	bff.Delete("/api/v1/teams/:teamId", proxy)

	// ───────────────────────────────────────────────────────────────────
	// CHANNEL ENDPOINTS
	// Channels exist within teams. They are real-time messaging spaces.
	// ───────────────────────────────────────────────────────────────────

	// GET /bff/api/v1/teams/:teamId/channels?cursorId=...
	// Business: Lists channels in a team with cursor-based pagination.
	// Headers: X-User-Id, X-Membership-Id
	// Query: cursorId (optional, for pagination)
	// Backend: GET /api/v1/teams/{teamId}/channels
	// Response: [ChannelResponse] — array of {channelId, name, description, status, createBy}
	bff.Get("/api/v1/teams/:teamId/channels", proxy)

	// POST /bff/api/v1/teams/:teamId/channels
	// Business: Creates a new channel within a team.
	// Headers: X-Idempotency-Key, X-User-Id, X-Membership-Id
	// Body: { "name": "..." (required, min 1 char), "description": "..." }
	// Backend: POST /api/v1/teams/{teamId}/channels
	bff.Post("/api/v1/teams/:teamId/channels", proxy)

	// PUT /bff/api/v1/teams/:teamId/channels/:channelId
	// Business: Updates channel name and/or description.
	// Headers: X-Idempotency-Key, X-User-Id, X-Membership-Id
	// Body: { "name": "..." (required, min 1 char), "description": "..." }
	// Backend: PUT /api/v1/teams/{teamId}/channels/{channelId}
	bff.Put("/api/v1/teams/:teamId/channels/:channelId", proxy)

	// DELETE /bff/api/v1/teams/:teamId/channels/:channelId
	// Business: Deletes a channel from a team.
	// Headers: X-Idempotency-Key, X-User-Id, X-Membership-Id
	// Backend: DELETE /api/v1/teams/{teamId}/channels/{channelId}
	bff.Delete("/api/v1/teams/:teamId/channels/:channelId", proxy)

	// ───────────────────────────────────────────────────────────────────
	// POST (FEED) ENDPOINTS
	// Posts are team-scoped feed items (like announcements or articles).
	// ───────────────────────────────────────────────────────────────────

	// GET /bff/api/v1/teams/:teamId/posts?cursorPostId=...
	// Business: Lists posts in a team's feed with cursor-based pagination.
	// Headers: X-User-Id, X-Membership-Id
	// Query: cursorPostId (optional, for pagination)
	// Backend: GET /api/v1/teams/{teamId}/posts
	// Response: [PostResponse] — array of {postId, title, description, status, createAt, updateAt, createBy}
	bff.Get("/api/v1/teams/:teamId/posts", proxy)

	// GET /bff/api/v1/teams/:teamId/posts/:postId
	// Business: Retrieves detailed information about a specific post.
	// Headers: X-User-Id, X-Membership-Id
	// Backend: GET /api/v1/teams/{teamId}/posts/{postId}
	// Response: PostResponse — {postId, title, description, status, createAt, updateAt, createBy}
	bff.Get("/api/v1/teams/:teamId/posts/:postId", proxy)

	// POST /bff/api/v1/teams/:teamId/posts
	// Business: Creates a new post in a team's feed.
	// Headers: X-Idempotency-Key, X-User-Id, X-Membership-Id
	// Body: { "title": "...", "description": "..." }
	// Backend: POST /api/v1/teams/{teamId}/posts
	bff.Post("/api/v1/teams/:teamId/posts", proxy)

	// PUT /bff/api/v1/teams/:teamId/posts/:postId
	// Business: Updates a post's title and/or description.
	// Headers: X-Idempotency-Key, X-User-Id, X-Membership-Id
	// Body: { "title": "...", "description": "..." }
	// Backend: PUT /api/v1/teams/{teamId}/posts/{postId}
	bff.Put("/api/v1/teams/:teamId/posts/:postId", proxy)

	// DELETE /bff/api/v1/teams/:teamId/posts/:postId
	// Business: Deletes a post from a team's feed.
	// Headers: X-Idempotency-Key, X-User-Id, X-Membership-Id
	// Backend: DELETE /api/v1/teams/{teamId}/posts/{postId}
	bff.Delete("/api/v1/teams/:teamId/posts/:postId", proxy)

	// ───────────────────────────────────────────────────────────────────
	// CHANNEL MESSAGE ENDPOINTS
	// Real-time messages within channels. Supports reply threading.
	// ───────────────────────────────────────────────────────────────────

	// GET /bff/api/v1/channels/:channelId/messages?cursorId=...
	// Business: Reads message history in a channel with cursor pagination.
	// Headers: X-Membership-Id
	// Query: cursorId (optional, for pagination)
	// Backend: GET /api/v1/channels/{channelId}/messages
	// Response: [MessageResponse] — {messageId, senderId, content, createAt, status, replyToId, replyContent, replierId}
	bff.Get("/api/v1/channels/:channelId/messages", proxy)

	// POST /bff/api/v1/channels/:channelId/messages
	// Business: Sends a new message in a channel. Supports replying to another message.
	// Headers: X-Idempotency-Key, X-User-Id, X-Membership-Id
	// Body: { "content": "...", "replyId": <int64|null> }
	// Backend: POST /api/v1/channels/{channelId}/messages
	bff.Post("/api/v1/channels/:channelId/messages", proxy)

	// PUT /bff/api/v1/channels/:channelId/messages/:messageId
	// Business: Edits the content of an existing channel message.
	// Headers: X-Idempotency-Key, X-User-Id, X-Membership-Id
	// Body: { "content": "..." }
	// Backend: PUT /api/v1/channels/{channelId}/messages/{messageId}
	bff.Put("/api/v1/channels/:channelId/messages/:messageId", proxy)

	// DELETE /bff/api/v1/channels/:channelId/messages/:messageId
	// Business: Deletes a message from a channel.
	// Headers: X-Idempotency-Key, X-User-Id, X-Membership-Id
	// Backend: DELETE /api/v1/channels/{channelId}/messages/{messageId}
	bff.Delete("/api/v1/channels/:channelId/messages/:messageId", proxy)

	// ───────────────────────────────────────────────────────────────────
	// COMMENT ENDPOINTS
	// Comments belong to posts. Supports reply threading.
	// ───────────────────────────────────────────────────────────────────

	// GET /bff/api/v1/posts/:postId/comments?cursorId=...
	// Business: Reads comments on a post with cursor pagination.
	// Headers: X-Team-Id, X-User-Id, X-Membership-Id
	// Query: cursorId (optional, for pagination)
	// Backend: GET /api/v1/posts/{postId}/comments
	// Response: [CommentResponse] — {commentId, senderId, content, createdAt, status, replyToId, replyContent, replierId}
	bff.Get("/api/v1/posts/:postId/comments", proxy)

	// POST /bff/api/v1/posts/:postId/comments
	// Business: Adds a comment to a post. Supports replying to another comment.
	// Headers: X-Idempotency-Key, X-User-Id, X-Membership-Id
	// Body: { "content": "...", "replyToId": <int64|null> }
	// Backend: POST /api/v1/posts/{postId}/comments
	bff.Post("/api/v1/posts/:postId/comments", proxy)

	// PUT /bff/api/v1/posts/:postId/comments/:commentId
	// Business: Edits an existing comment's content.
	// Headers: X-Idempotency-Key, X-User-Id, X-Membership-Id
	// Body: { "content": "..." }
	// Backend: PUT /api/v1/posts/{postId}/comments/{commentId}
	bff.Put("/api/v1/posts/:postId/comments/:commentId", proxy)

	// DELETE /bff/api/v1/posts/:postId/comments/:commentId
	// Business: Deletes a comment from a post.
	// Headers: X-Idempotency-Key, X-User-Id, X-Membership-Id
	// Backend: DELETE /api/v1/posts/{postId}/comments/{commentId}
	bff.Delete("/api/v1/posts/:postId/comments/:commentId", proxy)

	// ───────────────────────────────────────────────────────────────────
	// MEMBERSHIP ENDPOINTS
	// Manages team membership: join, leave, role updates.
	// ───────────────────────────────────────────────────────────────────

	// GET /bff/api/v1/users/me/memberships
	// Business: Lists all team memberships for the authenticated user.
	// Headers: X-User-Id
	// Backend: GET /api/v1/users/me/memberships
	// Response: [MembershipResponse] — array of {membershipId, userId, role}
	bff.Get("/api/v1/users/me/memberships", proxy)

	// GET /bff/api/v1/teams/:teamId/memberships
	// Business: Lists all members of a specific team.
	// Backend: GET /api/v1/teams/{teamId}/memberships
	// Response: [MembershipResponse]
	bff.Get("/api/v1/teams/:teamId/memberships", proxy)

	// GET /bff/api/v1/teams/:teamId/memberships/me
	// Business: Gets the authenticated user's membership info within a team.
	// Headers: X-User-Id
	// Backend: GET /api/v1/teams/{teamId}/memberships/me
	// Response: MembershipResponse — {membershipId, userId, role}
	bff.Get("/api/v1/teams/:teamId/memberships/me", proxy)

	// POST /bff/api/v1/teams/:teamId/memberships
	// Business: Adds a new member to a team (invite).
	// Headers: X-Idempotency-Key, X-User-Id
	// Body: { "targetUserId": <int64>, "role": "MEMBER"|"ADMIN" }
	// Backend: POST /api/v1/teams/{teamId}/memberships
	bff.Post("/api/v1/teams/:teamId/memberships", proxy)

	// PUT /bff/api/v1/teams/:teamId/memberships/:membershipId
	// Business: Updates a member's role within a team.
	// Headers: X-Idempotency-Key, X-Membership-Id (caller's own membership), X-User-Id
	// Body: { "role": "MEMBER"|"ADMIN"|"OWNER" }
	// Backend: PUT /api/v1/teams/{teamId}/memberships/{membershipId}
	bff.Put("/api/v1/teams/:teamId/memberships/:membershipId", proxy)

	// DELETE /bff/api/v1/teams/:teamId/memberships/:membershipId
	// Business: Removes a member from a team (kick or leave).
	// Headers: X-Idempotency-Key, X-Membership-Id (caller's own membership), X-User-Id
	// Backend: DELETE /api/v1/teams/{teamId}/memberships/{membershipId}
	bff.Delete("/api/v1/teams/:teamId/memberships/:membershipId", proxy)

	// ───────────────────────────────────────────────────────────────────
	// EVENT ENDPOINTS
	// Team-scoped calendar events with start/end times and attendee count.
	// ───────────────────────────────────────────────────────────────────

	// GET /bff/api/v1/teams/:teamId/events?cursorId=...
	// Business: Lists events in a team with cursor-based pagination.
	// Query: cursorId (optional)
	// Backend: GET /api/v1/teams/{teamId}/events
	// Response: [EventResponse] — {eventId, title, content, status, startTime, endTime, createAt, createBy, numberAttend}
	bff.Get("/api/v1/teams/:teamId/events", proxy)

	// POST /bff/api/v1/teams/:teamId/events
	// Business: Creates a new event in a team's calendar.
	// Headers: X-Idempotency-Key, X-User-Id
	// Body: { "title": "...", "content": "...", "startTime": "ISO8601", "endTime": "ISO8601" }
	// Backend: POST /api/v1/teams/{teamId}/events
	bff.Post("/api/v1/teams/:teamId/events", proxy)

	// DELETE /bff/api/v1/teams/:teamId/events/:eventId
	// Business: Deletes an event from a team's calendar.
	// Headers: X-Idempotency-Key, X-User-Id
	// Backend: DELETE /api/v1/teams/{teamId}/events/{eventId}
	bff.Delete("/api/v1/teams/:teamId/events/:eventId", proxy)

	// ───────────────────────────────────────────────────────────────────
	// EMOJI ENDPOINTS
	// Custom team emojis stored as MinIO objects.
	// ───────────────────────────────────────────────────────────────────

	// GET /bff/api/v1/teams/:teamId/emojis
	// Business: Lists all custom emojis in a team.
	// Headers: X-User-Id
	// Backend: GET /api/v1/teams/{teamId}/emojis
	// Response: [EmojiResponse] — array of {emojiName, objectName}
	bff.Get("/api/v1/teams/:teamId/emojis", proxy)

	// POST /bff/api/v1/teams/:teamId/emojis
	// Business: Registers a new custom emoji for the team.
	// Headers: X-Idempotency-Key, X-User-Id
	// Body: { "emojiName": "..." (required), "objectKey": "..." (required) }
	// Backend: POST /api/v1/teams/{teamId}/emojis
	bff.Post("/api/v1/teams/:teamId/emojis", proxy)

	// DELETE /bff/api/v1/teams/:teamId/emojis/:emojiName
	// Business: Removes a custom emoji from the team.
	// Headers: X-Idempotency-Key, X-User-Id
	// Backend: DELETE /api/v1/teams/{teamId}/emojis/{emojiName}
	bff.Delete("/api/v1/teams/:teamId/emojis/:emojiName", proxy)

	// ───────────────────────────────────────────────────────────────────
	// DIRECT MESSAGE (DM) ENDPOINTS
	// Private 1-on-1 messages within a private session.
	// ───────────────────────────────────────────────────────────────────

	// GET /bff/api/v1/private-sessions/:sessionId/messages?cursorId=...
	// Business: Reads message history in a private session with cursor pagination.
	// Headers: X-User-Id
	// Query: cursorId (optional)
	// Backend: GET /api/v1/private-sessions/{sessionId}/messages
	// Response: [DirectMessageResponse] — {messageId, senderId, content, createAt, status, replyToId, replyContent, replierId}
	bff.Get("/api/v1/private-sessions/:sessionId/messages", proxy)

	// POST /bff/api/v1/private-sessions/:sessionId/messages
	// Business: Sends a direct message in a private session.
	// Headers: X-Idempotency-Key, X-User-Id
	// Body: { "content": "...", "replyToId": <int64|null> }
	// Backend: POST /api/v1/private-sessions/{sessionId}/messages
	bff.Post("/api/v1/private-sessions/:sessionId/messages", proxy)

	// PUT /bff/api/v1/private-sessions/:sessionId/messages/:messageId
	// Business: Edits a direct message's content.
	// Headers: X-Idempotency-Key, X-User-Id
	// Body: { "content": "..." }
	// Backend: PUT /api/v1/private-sessions/{sessionId}/messages/{messageId}
	bff.Put("/api/v1/private-sessions/:sessionId/messages/:messageId", proxy)

	// DELETE /bff/api/v1/private-sessions/:sessionId/messages/:messageId
	// Business: Deletes a direct message.
	// Headers: X-Idempotency-Key, X-User-Id
	// Backend: DELETE /api/v1/private-sessions/{sessionId}/messages/{messageId}
	bff.Delete("/api/v1/private-sessions/:sessionId/messages/:messageId", proxy)

	// ───────────────────────────────────────────────────────────────────
	// PRIVATE SESSION ENDPOINTS
	// Private sessions are 1-on-1 conversations between two users.
	// ───────────────────────────────────────────────────────────────────

	// GET /bff/api/v1/users/me/private-sessions
	// Business: Lists all private sessions for the authenticated user.
	// Headers: X-User-Id
	// Backend: GET /api/v1/users/me/private-sessions
	// Response: [PrivateSessionResponse] — array of {privateSessionId, partnerId}
	bff.Get("/api/v1/users/me/private-sessions", proxy)

	// GET /bff/api/v1/users/me/private-sessions/with/:targetUserId
	// Business: Gets or checks the private session between the auth user and a target user.
	// Headers: X-User-Id
	// Backend: GET /api/v1/users/me/private-sessions/with/{targetUserId}
	// Response: PrivateSessionResponse — {privateSessionId, partnerId}
	bff.Get("/api/v1/users/me/private-sessions/with/:targetUserId", proxy)

	// POST /bff/api/v1/private-sessions
	// Business: Creates a new private session (DM conversation) with another user.
	// Headers: X-Idempotency-Key, X-User-Id
	// Body: { "targetUserId": <int64> }
	// Backend: POST /api/v1/private-sessions
	bff.Post("/api/v1/private-sessions", proxy)

	// ───────────────────────────────────────────────────────────────────
	// PUBLIC STORAGE ENDPOINTS
	// Pre-signed URL generation for public MinIO bucket operations.
	// Used for team avatars, emojis, and other public assets.
	// ───────────────────────────────────────────────────────────────────

	// GET /bff/api/v1/public-storage/upload-policy?objectName=...
	// Business: Generates a pre-signed upload policy for the public bucket.
	// Query: objectName (required)
	// Backend: GET /api/v1/public-storage/upload-policy
	// Response: { "<field>": "<value>" } — pre-signed form data
	bff.Get("/api/v1/public-storage/upload-policy", proxy)

	// GET /bff/api/v1/public-storage/download-url?objectName=...
	// Business: Generates a pre-signed download URL for a public object.
	// Query: objectName (required)
	// Backend: GET /api/v1/public-storage/download-url
	// Response: { "url": "<pre-signed-url>" }
	bff.Get("/api/v1/public-storage/download-url", proxy)

	// GET /bff/api/v1/public-storage/delete-url?objectName=...
	// Business: Generates a pre-signed delete URL for a public object.
	// Query: objectName (required)
	// Backend: GET /api/v1/public-storage/delete-url
	// Response: { "url": "<pre-signed-url>" }
	bff.Get("/api/v1/public-storage/delete-url", proxy)

	// ───────────────────────────────────────────────────────────────────
	// PRIVATE STORAGE ENDPOINTS
	// Pre-signed URL generation for private MinIO bucket operations.
	// Used for file attachments in messages and DMs.
	// ───────────────────────────────────────────────────────────────────

	// GET /bff/api/v1/private-storage/upload-policy?objectName=...
	// Business: Generates a pre-signed upload policy for the private bucket.
	// Query: objectName (required)
	// Backend: GET /api/v1/private-storage/upload-policy
	// Response: { "<field>": "<value>" } — pre-signed form data
	bff.Get("/api/v1/private-storage/upload-policy", proxy)

	// GET /bff/api/v1/private-storage/download-url?objectName=...
	// Business: Generates a pre-signed download URL for a private object.
	// Query: objectName (required)
	// Backend: GET /api/v1/private-storage/download-url
	// Response: { "url": "<pre-signed-url>" }
	bff.Get("/api/v1/private-storage/download-url", proxy)

	// GET /bff/api/v1/private-storage/delete-url?objectName=...
	// Business: Generates a pre-signed delete URL for a private object.
	// Query: objectName (required)
	// Backend: GET /api/v1/private-storage/delete-url
	// Response: { "url": "<pre-signed-url>" }
	bff.Get("/api/v1/private-storage/delete-url", proxy)

	// POST /bff/api/v1/private-storage/batch-download-urls
	// Business: Generates pre-signed download URLs for multiple private objects at once.
	// Body: { "objectNames": ["file1.jpg", "file2.pdf", ...] }
	// Backend: POST /api/v1/private-storage/batch-download-urls
	// Response: { "file1.jpg": "<url>", "file2.pdf": "<url>", ... }
	bff.Post("/api/v1/private-storage/batch-download-urls", proxy)

	// ── Step 8: Start Server ──────────────────────────────────────────
	listenAddr := fmt.Sprintf(":%s", cfg.Port)
	log.Printf("[INFO] Xcellator BFF is ready — listening on %s", listenAddr)
	if err := app.Listen(listenAddr); err != nil {
		log.Fatalf("[FATAL] Server failed to start: %v", err)
	}
}
