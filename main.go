// hg8145v5-mcp is a small resident service for the Huawei HG8145V5 ONT. One binary does three
// things: it serves a set of device tools over MCP (JSON-RPC 2.0 on stdio), serves the same
// tools over a LAN-only HTTP API, and optionally runs a DNS ad/tracker filter.
//
// Design constraints (see docs/architecture.md):
//   - The device has no Python/Node/package manager and a read-only, nearly full root
//     filesystem. Only /mnt/jffs2 is writable, with limited space. This must be a single
//     static executable (CGO_ENABLED=0, no dependency on the device's libc).
//   - Never modify OEM files and never store a credential: every data source is a plain read
//     of /proc, a filesystem stat, or a credential-free local tool (hostapd_cli,
//     displayvoicelog.sh). Optional settings come from the environment.
//   - Writes exist, but only as a small, explicitly named set of guarded actions
//     (actions.go, filter.go), exposed identically over MCP and HTTP (httpapi.go).
//   - The process is started at boot by the debug_start.sh hook chain (docs/install.md), not
//     by modifying the root filesystem.
//
// Build (CI does the same, see .github/workflows/build.yml):
//
//	GOOS=linux GOARCH=arm GOARM=5 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o hg8145v5-mcp-arm5 .
//
// GOARM=5 (soft float) is deliberate: the device kernel exposes no VFP, and a GOARM=7 build
// dies with SIGILL on it.
package main

import (
	"bufio"
	"encoding/json"
	"os"
	"runtime/debug"
	"strings"
	"time"
)

const serverVersion = "0.2.0"

// --- JSON-RPC 2.0 / MCP wire types -----------------------------------------

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type toolDef struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema interface{} `json:"inputSchema"`
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// --- Tools -------------------------------------------------------------------
// Read tools all draw from the same cached snapshot as the HTTP API
// (cachedMetrics in metrics.go), so a burst of tool calls costs one collection,
// and the two interfaces can never disagree about what the device looks like.

var emptyObjectSchema = map[string]any{"type": "object", "properties": map[string]any{}}

var tools = []toolDef{
	{
		Name:        "all_metrics",
		Description: "Everything in one snapshot: system, CPU, memory, storage, interfaces, Wi-Fi clients, voice registration, connection counts, and service info.",
		InputSchema: emptyObjectSchema,
	},
	{
		Name:        "system_info",
		Description: "Kernel version, uptime, load averages, CPU busy percent, and memory usage of the modem.",
		InputSchema: emptyObjectSchema,
	},
	{
		Name:        "network_interfaces",
		Description: "LAN/WAN/Wi-Fi interface byte, packet, error and drop counters (no MAC or IP addresses).",
		InputSchema: emptyObjectSchema,
	},
	{
		Name:        "wifi_clients_count",
		Description: "Number of Wi-Fi clients currently associated, per radio. Counts only, no client identifiers.",
		InputSchema: emptyObjectSchema,
	},
	{
		Name:        "voice_registration",
		Description: "SIP/voice registration status and the most recent registration abnormalities (e.g. SIP 403/408).",
		InputSchema: emptyObjectSchema,
	},
	{
		Name:        "storage",
		Description: "Total and free space of each real filesystem (flash, tmpfs, rootfs). Free flash on /mnt/jffs2 is the key number: it limits what can be installed.",
		InputSchema: emptyObjectSchema,
	},
	{
		Name:        "connections",
		Description: "Tracked connection count against its limit, and how many LAN neighbours the modem has recently seen.",
		InputSchema: emptyObjectSchema,
	},
	{
		Name:        "service_info",
		Description: "This MCP server's own version, start time, and the address its HTTP API is bound to.",
		InputSchema: emptyObjectSchema,
	},
	{
		Name:        "dns_filter",
		Description: "Optional DNS ad/tracker filter: whether it is running, how many domains are loaded in RAM, last list refresh, and query/blocked counters. Never returns domain names.",
		InputSchema: emptyObjectSchema,
	},
	{
		Name:        "dns_filter_pause",
		Description: "WRITE: pause DNS ad/tracker blocking for up to an hour (0 resumes). Like Pi-hole's disable button; in RAM only.",
		InputSchema: map[string]any{
			"type":     "object",
			"required": []string{"seconds"},
			"properties": map[string]any{
				"seconds": map[string]any{"type": "integer", "minimum": 0, "maximum": 3600, "description": "0 resumes blocking."},
			},
		},
	},
	{
		Name:        "dns_filter_check",
		Description: "Read-only: would the DNS filter block this domain, and why? Use it to debug a false positive; nothing is logged or stored.",
		InputSchema: map[string]any{
			"type":     "object",
			"required": []string{"domain"},
			"properties": map[string]any{
				"domain": map[string]any{"type": "string", "description": "e.g. example.com"},
			},
		},
	},
	{
		Name:        "dns_filter_update",
		Description: "WRITE: re-download the DNS filter lists now (Pi-hole's 'update gravity').",
		InputSchema: emptyObjectSchema,
	},
	{
		Name:        "wifi_kick_client",
		Description: "WRITE: disconnect one Wi-Fi client (deauthenticate). The client may reconnect immediately; this is not a ban. Get the radio name from wifi_clients_count.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"interface": map[string]any{"type": "string", "description": "Radio interface name, e.g. vap0"},
				"mac":       map[string]any{"type": "string", "description": "MAC address of the station to disconnect, aa:bb:cc:dd:ee:ff"},
			},
			"required": []string{"interface", "mac"},
		},
	},
	{
		Name:        "reboot_modem",
		Description: "WRITE: reboot the modem. This takes the household's only internet, Wi-Fi and phone line down for about 3 minutes. Refused unless confirm is exactly REBOOT, and refused if the modem booted less than 3 minutes ago.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"confirm":       map[string]any{"type": "string", "description": "Must be exactly REBOOT"},
				"delay_seconds": map[string]any{"type": "integer", "description": "Seconds to wait before rebooting, 5 to 300 (default 10)"},
			},
			"required": []string{"confirm"},
		},
	},
}

func readFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func jsonText(v any) (string, *rpcError) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", &rpcError{Code: -32000, Message: err.Error()}
	}
	return string(b), nil
}

func actionResult(out string, err error) (string, *rpcError) {
	if err != nil {
		return "", &rpcError{Code: -32000, Message: err.Error()}
	}
	return out, nil
}

func callTool(name string, args json.RawMessage) (string, *rpcError) {
	switch name {
	case "all_metrics":
		return jsonText(cachedMetrics())
	case "system_info":
		return jsonText(cachedMetrics().System)
	case "network_interfaces":
		return jsonText(cachedMetrics().Ifaces)
	case "wifi_clients_count":
		return jsonText(cachedMetrics().WifiClients)
	case "voice_registration":
		return jsonText(cachedMetrics().VoiceReg)
	case "storage":
		return jsonText(cachedMetrics().Storage)
	case "connections":
		return jsonText(cachedMetrics().Connections)
	case "service_info":
		return jsonText(cachedMetrics().Service)
	case "dns_filter":
		return jsonText(filterStats())
	case "wifi_kick_client":
		return actionResult(toolWifiKickClient(args))
	case "reboot_modem":
		return actionResult(toolRebootModem(args))
	case "dns_filter_pause":
		return actionResult(toolDNSFilterPause(args))
	case "dns_filter_update":
		return actionResult(toolDNSFilterUpdate(args))
	case "dns_filter_check":
		return actionResult(toolDNSFilterCheck(args))
	}
	return "", &rpcError{Code: -32602, Message: "unknown tool: " + name}
}

// --- JSON-RPC loop -----------------------------------------------------------

func main() {
	// Used by service.sh whenever the service exits, so a crashed or killed process can
	// never leave the DNS redirect behind. No-op unless FILTER_TAKEOVER=on.
	if len(os.Args) > 1 && os.Args[1] == "-dns-cleanup" {
		removeTakeover()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "-guard-remove" { // used by service.sh stop, see portguard.go
		removeGuard()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "-dns-watch" { // health watcher, see takeover.go
		dnsWatch()
		return
	}

	// Small footprint on a 256MB shared gateway: collect garbage early and
	// soft-cap the Go heap well below what the box can spare.
	debug.SetGCPercent(50)
	debug.SetMemoryLimit(48 << 20) // headroom for the optional in-RAM DNS filter lists

	// Buffered by 1 so startAPIServer's goroutine can send the resolved
	// address without blocking on anything reading it -- startMDNS below
	// reads it in its own goroutine, on its own time, never this one.
	apiAddrReady := make(chan string, 1)
	startAPIServer(apiAddrReady)
	startDNSFilter() // no-op unless FILTER_TAKEOVER/FILTER_PORT is set; see filter.go
	startPortGuard() // every port we open is LAN-only at the firewall too; PORT_GUARD=off disables
	go func() {
		startMDNS(<-apiAddrReady)
	}()

	// The resident service (started by service.sh) has nobody on stdin: it only serves the
	// HTTP API and the DNS filter. Block here instead of reading stdin, so the supervisor can
	// run it directly and notice the moment it exits. An MCP client that spawns this binary
	// itself (e.g. over SSH) does not set this and gets the normal stdio loop.
	if os.Getenv("HG_NO_STDIO") == "1" {
		select {}
	}

	reader := bufio.NewReader(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)
	defer writer.Flush()

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var req rpcRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			continue
		}

		resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}

		switch req.Method {
		case "initialize":
			resp.Result = map[string]any{
				"protocolVersion": "2024-11-05",
				"serverInfo": map[string]any{
					"name":    "hg8145v5-mcp",
					"version": serverVersion,
				},
				"capabilities": map[string]any{
					"tools": map[string]any{},
				},
			}

		case "tools/list":
			resp.Result = map[string]any{"tools": tools}

		case "tools/call":
			var params toolCallParams
			_ = json.Unmarshal(req.Params, &params)
			text, rpcErr := callTool(params.Name, params.Arguments)
			if rpcErr != nil {
				resp.Error = rpcErr
			} else {
				resp.Result = map[string]any{
					"content": []map[string]any{
						{"type": "text", "text": text},
					},
				}
			}

		case "ping":
			resp.Result = map[string]any{"time": time.Now().UTC().Format(time.RFC3339)}

		default:
			resp.Error = &rpcError{Code: -32601, Message: "method not found: " + req.Method}
		}

		b, _ := json.Marshal(resp)
		writer.Write(b)
		writer.WriteString("\n")
		writer.Flush()
	}
}
