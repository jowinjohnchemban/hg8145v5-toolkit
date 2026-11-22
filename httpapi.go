// httpapi.go exposes every MCP tool over HTTP, through the same callTool
// function the stdio interface uses, so the two cannot behave differently:
//
//	GET  /api/tools            list of tools (same definitions MCP serves)
//	GET  /api/tools/<name>     a read tool, JSON result
//	POST /api/tools/<name>     a write tool, JSON body = the tool's arguments
//	GET  /api/metrics          the full snapshot (same as the all_metrics tool)
//
// Writes on an unauthenticated LAN endpoint need care, and there is
// deliberately no stored password (see docs/security.md). Instead the guards are
// structural, aimed at the realistic threat -- a web page open in a browser
// on the LAN trying to make that browser call this device -- plus basic
// hygiene:
//
//   - POST only, with Content-Type application/json. A cross-site <form>
//     cannot send that, and a cross-site script would need a CORS preflight,
//     which this server never grants.
//   - Any request carrying an Origin header is refused: browsers add it to
//     cross-origin requests, real API clients (curl, scripts, hubs) do not.
//   - The Host header must be an IP address or a .local name, which blocks
//     DNS-rebinding (an attacker's domain pointed at this IP). This applies
//     to reads too, so rebinding cannot read the data either.
//   - Writes are rate limited, and each is audit-logged with its source.
//   - Optional hardening, off by default: API_WRITES=off disables HTTP writes
//     entirely, and API_WRITE_TOKEN (if set) must be sent as a Bearer token.
//
// What these guards do not do: stop another device on the LAN that can speak
// HTTP from calling the write endpoints. That is inherent to unauthenticated
// LAN access; API_WRITES=off is the switch for anyone who does not want it.
package main

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const writeMinInterval = 3 * time.Second

var (
	writeMu   sync.Mutex
	lastWrite time.Time
)

// writeTools are the tools that change state. Everything else is read-only
// and served on GET.
var writeTools = map[string]bool{
	"wifi_kick_client": true,
	"reboot_modem":     true,

	"dns_filter_pause":  true,
	"dns_filter_update": true,
	// Read-only, but takes a domain argument, so it is POST + JSON like the writes.
	"dns_filter_check": true,
}

func httpWritesEnabled() bool {
	return !strings.EqualFold(os.Getenv("API_WRITES"), "off")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// hostAllowed reports whether the request's Host header names an IP address
// or a .local name, the only ways a LAN client legitimately reaches this
// device. A public DNS name here means a browser was redirected to us by an
// attacker-controlled domain.
func hostAllowed(hostHeader string) bool {
	host := hostHeader
	if h, _, err := net.SplitHostPort(hostHeader); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if net.ParseIP(host) != nil {
		return true
	}
	return strings.HasSuffix(strings.ToLower(host), ".local")
}

func hostGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hostAllowed(r.Host) {
			writeError(w, http.StatusForbidden, "Host header must be an IP address or a .local name")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// checkWriteRequest applies the write-only guards. It returns an HTTP status
// and message, or 0 if the request may proceed.
func checkWriteRequest(r *http.Request) (int, string) {
	if !httpWritesEnabled() {
		return http.StatusForbidden, "HTTP writes are disabled (API_WRITES=off)"
	}
	if r.Header.Get("Origin") != "" {
		return http.StatusForbidden, "browser-originated requests (Origin header) are refused for writes"
	}
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mt != "application/json" {
		return http.StatusUnsupportedMediaType, "writes require Content-Type: application/json"
	}
	if token := os.Getenv("API_WRITE_TOKEN"); token != "" {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			return http.StatusUnauthorized, "missing or wrong bearer token"
		}
	}
	writeMu.Lock()
	defer writeMu.Unlock()
	if time.Since(lastWrite) < writeMinInterval {
		return http.StatusTooManyRequests, "writes are rate limited; try again in a few seconds"
	}
	lastWrite = time.Now()
	return 0, ""
}

func toolsHandler(w http.ResponseWriter, r *http.Request) {
	name := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/tools"), "/")

	if name == "" {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			writeError(w, http.StatusMethodNotAllowed, "use GET")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tools": tools})
		return
	}

	var args json.RawMessage
	isWrite := writeTools[name]
	if isWrite {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			writeError(w, http.StatusMethodNotAllowed, name+" changes device state: use POST")
			return
		}
		if status, msg := checkWriteRequest(r); status != 0 {
			auditAction("http write %s REFUSED (%d %s) from %s", name, status, msg, r.RemoteAddr)
			writeError(w, status, msg)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
		if err != nil {
			writeError(w, http.StatusBadRequest, "could not read request body: "+err.Error())
			return
		}
		args = body
		auditAction("http write %s requested from %s", name, r.RemoteAddr)
	} else if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed, name+" is read-only: use GET")
		return
	}

	text, rpcErr := callTool(name, args)
	if rpcErr != nil {
		status := http.StatusBadRequest
		if rpcErr.Code == -32602 {
			status = http.StatusNotFound
		}
		writeError(w, status, rpcErr.Message)
		return
	}

	if isWrite {
		writeJSON(w, http.StatusOK, map[string]string{"result": text})
		return
	}
	// Read tools already return JSON text; pass it through unchanged.
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, text)
}
