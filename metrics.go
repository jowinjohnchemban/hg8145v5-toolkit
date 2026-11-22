// metrics.go exposes a small read-only JSON API alongside the stdio MCP
// server, for consumers that want machine-readable status (e.g. a separate
// dashboard, a scheduled check) without speaking JSON-RPC over stdio. It
// surfaces every read-only data point the MCP tools in main.go can produce,
// parsed into typed fields rather than the preformatted text the stdio
// tools return.
//
// Binding: resolved at startup, never hardcoded. It binds to the first IPv4
// address of the LAN bridge interface (first up interface named "br*", or the
// one named by API_IFACE), not 0.0.0.0, so it is reachable from the LAN/Wi-Fi
// like the stock admin GUI without opening a port on the WAN interface. If no
// such address is found it falls back to 127.0.0.1 (unreachable from the LAN,
// but never exposed). API_PORT changes the port (default 8099). API_ADDR
// overrides everything (e.g. "0.0.0.0:8099") -- only after separately
// confirming that port is not reachable from the WAN side.
//
// No history is kept on the device -- every request is a fresh snapshot; a
// client that wants a time series polls repeatedly and keeps it itself.
package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const apiDefaultPort = "8099"

type systemInfo struct {
	Kernel        string  `json:"kernel"`
	UptimeSeconds float64 `json:"uptime_seconds"`
	Load1         float64 `json:"load1"`
	Load5         float64 `json:"load5"`
	Load15        float64 `json:"load15"`
	ProcsRunning  int     `json:"procs_running"`
	ProcsTotal    int     `json:"procs_total"`
	MemTotalKB    uint64  `json:"mem_total_kb"`
	MemFreeKB     uint64  `json:"mem_free_kb"`
	MemCachedKB   uint64  `json:"mem_cached_kb"`
	MemBuffersKB  uint64  `json:"mem_buffers_kb"`
	// CPUBusyPercent is measured over a short sample (see sysextra.go), not
	// averaged since boot, so it reflects what the CPU is doing right now.
	CPUBusyPercent float64 `json:"cpu_busy_percent"`
	GoRuntime      string  `json:"go_runtime"`
}

type ifaceCounters struct {
	Name      string `json:"name"`
	Up        bool   `json:"up"`
	RxBytes   uint64 `json:"rx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	RxErrs    uint64 `json:"rx_errs"`
	RxDrop    uint64 `json:"rx_drop"`
	TxBytes   uint64 `json:"tx_bytes"`
	TxPackets uint64 `json:"tx_packets"`
	TxErrs    uint64 `json:"tx_errs"`
	TxDrop    uint64 `json:"tx_drop"`
}

type voiceRegistrationStatus struct {
	OK     bool     `json:"ok"`
	Detail string   `json:"detail"`
	Recent []string `json:"recent_abnormalities,omitempty"`
}

// wifiRadio is the associated-client count for one Wi-Fi radio interface.
// Only a count is reported, never the clients' MAC addresses -- same
// no-identifiers rule as the interface counters above.
type wifiRadio struct {
	Interface string `json:"interface"`
	State     string `json:"state,omitempty"` // hostapd's own state, e.g. ENABLED
	Clients   int    `json:"clients"`
	Error     string `json:"error,omitempty"`
}

type metricsSnapshot struct {
	TimeUnix          int64                   `json:"time_unix"`
	System            systemInfo              `json:"system"`
	Storage           []storageFS             `json:"storage"`
	Ifaces            []ifaceCounters         `json:"ifaces"`
	WifiClients       []wifiRadio             `json:"wifi_clients"`
	VoiceReg          voiceRegistrationStatus `json:"voice_registration"`
	Connections       connectionsInfo         `json:"connections"`
	ListeningTCPPorts []int                   `json:"listening_tcp_ports"`
	TopProcesses      []processInfo           `json:"top_processes"`
	Service           serviceInfo             `json:"service"`
}

// hostapdRadio is one hostapd control socket: the directory holding it and
// the interface name it controls. Discovered from the filesystem, never
// hardcoded, so a different radio layout needs no code change.
type hostapdRadio struct {
	CtrlDir string
	Iface   string
}

func listRadios() []hostapdRadio {
	var radios []hostapdRadio
	socks, _ := filepath.Glob("/var/run/hostapd-*/*")
	for _, s := range socks {
		radios = append(radios, hostapdRadio{CtrlDir: filepath.Dir(s), Iface: filepath.Base(s)})
	}
	return radios
}

func hostapdCLI(r hostapdRadio, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	full := append([]string{"-p", r.CtrlDir, "-i", r.Iface}, args...)
	return exec.CommandContext(ctx, "hostapd_cli", full...).CombinedOutput()
}

// macLine matches a bare station MAC address line, which is how
// `hostapd_cli all_sta` starts each station's block.
var macLine = regexp.MustCompile(`^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$`)

// collectWifiClients counts associated stations per radio by asking hostapd
// directly, through its control sockets under /var/run/hostapd-*/. This
// replaced an earlier attempt that assumed a standalone `display` binary
// (it doesn't exist: the vendor `display ...` commands live inside the
// console daemon) and a later idea of driving that console over local
// telnet, which would have required storing a login password on the
// device. hostapd_cli needs no credentials, and was confirmed on-device to
// work from the same unprivileged account this service runs as.
//
// Radios are discovered from the socket directory, not hardcoded, so a
// different SSID/radio layout needs no code change.
func collectWifiClients() []wifiRadio {
	var radios []wifiRadio
	for _, hr := range listRadios() {
		r := wifiRadio{Interface: hr.Iface}

		if out, err := hostapdCLI(hr, "all_sta"); err != nil {
			r.Error = err.Error()
		} else {
			for _, line := range strings.Split(string(out), "\n") {
				if macLine.MatchString(strings.TrimSpace(line)) {
					r.Clients++
				}
			}
		}

		// Status is best-effort extra detail: a failure here must not hide
		// the client count above, so it is simply left empty.
		if out, err := hostapdCLI(hr, "status"); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if v, ok := strings.CutPrefix(strings.TrimSpace(line), "state="); ok {
					r.State = v
					break
				}
			}
		}
		radios = append(radios, r)
	}
	return radios
}

func parseMeminfoKB(raw, key string) uint64 {
	for _, line := range strings.Split(raw, "\n") {
		if !strings.HasPrefix(line, key+":") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			v, _ := strconv.ParseUint(fields[1], 10, 64)
			return v
		}
	}
	return 0
}

func collectSystemInfo() systemInfo {
	var si systemInfo
	si.GoRuntime = runtime.Version() + " on " + runtime.GOOS + "/" + runtime.GOARCH

	if uname, err := readFile("/proc/version"); err == nil {
		si.Kernel = strings.TrimSpace(uname)
	}

	if uptime, err := readFile("/proc/uptime"); err == nil {
		fields := strings.Fields(uptime)
		if len(fields) >= 1 {
			si.UptimeSeconds, _ = strconv.ParseFloat(fields[0], 64)
		}
	}

	if loadavg, err := readFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(loadavg)
		if len(fields) >= 4 {
			si.Load1, _ = strconv.ParseFloat(fields[0], 64)
			si.Load5, _ = strconv.ParseFloat(fields[1], 64)
			si.Load15, _ = strconv.ParseFloat(fields[2], 64)
			if running, total, ok := strings.Cut(fields[3], "/"); ok {
				si.ProcsRunning, _ = strconv.Atoi(running)
				si.ProcsTotal, _ = strconv.Atoi(total)
			}
		}
	}

	if meminfo, err := readFile("/proc/meminfo"); err == nil {
		si.MemTotalKB = parseMeminfoKB(meminfo, "MemTotal")
		si.MemFreeKB = parseMeminfoKB(meminfo, "MemFree")
		si.MemCachedKB = parseMeminfoKB(meminfo, "Cached")
		si.MemBuffersKB = parseMeminfoKB(meminfo, "Buffers")
	}

	si.CPUBusyPercent = collectCPUBusyPercent()

	return si
}

func collectIfaceCounters() []ifaceCounters {
	var out []ifaceCounters
	dev, err := readFile("/proc/net/dev")
	if err != nil {
		return out
	}
	for i, line := range strings.Split(dev, "\n") {
		if i < 2 || strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		f := strings.Fields(parts[1])
		// /proc/net/dev columns: rx(bytes packets errs drop fifo frame compressed multicast) tx(bytes packets errs drop fifo colls carrier compressed)
		if len(f) < 16 {
			continue
		}
		c := ifaceCounters{Name: name}
		if ifc, err := net.InterfaceByName(name); err == nil {
			c.Up = ifc.Flags&net.FlagUp != 0
		}
		c.RxBytes, _ = strconv.ParseUint(f[0], 10, 64)
		c.RxPackets, _ = strconv.ParseUint(f[1], 10, 64)
		c.RxErrs, _ = strconv.ParseUint(f[2], 10, 64)
		c.RxDrop, _ = strconv.ParseUint(f[3], 10, 64)
		c.TxBytes, _ = strconv.ParseUint(f[8], 10, 64)
		c.TxPackets, _ = strconv.ParseUint(f[9], 10, 64)
		c.TxErrs, _ = strconv.ParseUint(f[10], 10, 64)
		c.TxDrop, _ = strconv.ParseUint(f[11], 10, 64)
		if c.RxBytes == 0 && c.TxBytes == 0 {
			continue // skip idle/unused virtual interfaces
		}
		out = append(out, c)
	}
	return out
}

// collectVoiceRegistrationStatus shells out to the vendor's own log command
// the same way an interactive operator would. Like wifi_clients_count in
// main.go, the plain-exec-vs-pty question for this CLI path is unverified --
// if the command isn't reachable this way, the status reports that plainly
// instead of inventing a result.
func collectVoiceRegistrationStatus() voiceRegistrationStatus {
	if _, err := exec.LookPath("displayvoicelog.sh"); err != nil {
		return voiceRegistrationStatus{OK: false, Detail: "displayvoicelog.sh not reachable via plain exec from this process (unverified path, see mcp-server/README.md)"}
	}
	out, err := exec.Command("displayvoicelog.sh").CombinedOutput()
	if err != nil {
		return voiceRegistrationStatus{OK: false, Detail: err.Error()}
	}

	var recent []string
	for _, l := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if strings.Contains(l, "Registration") {
			recent = append(recent, strings.TrimSpace(l))
		}
	}
	const keepLast = 10
	if len(recent) > keepLast {
		recent = recent[len(recent)-keepLast:]
	}
	if len(recent) == 0 {
		return voiceRegistrationStatus{OK: true, Detail: "no recent registration abnormalities"}
	}
	return voiceRegistrationStatus{OK: false, Detail: "recent registration abnormalities logged", Recent: recent}
}

func collectMetrics() metricsSnapshot {
	return metricsSnapshot{
		TimeUnix:          time.Now().Unix(),
		System:            collectSystemInfo(),
		Storage:           collectStorage(),
		Ifaces:            collectIfaceCounters(),
		WifiClients:       collectWifiClients(),
		VoiceReg:          collectVoiceRegistrationStatus(),
		Connections:       collectConnections(),
		ListeningTCPPorts: collectListeningPorts(),
		TopProcesses:      collectTopProcesses(10),
		Service:           collectServiceInfo(),
	}
}

// The voice and Wi-Fi fields spawn vendor scripts, which is expensive on this
// box, so concurrent or rapid requests share one snapshot for snapTTL.
const snapTTL = 2 * time.Second

var (
	snapMu   sync.Mutex
	snapAt   time.Time
	snapLast metricsSnapshot
)

func cachedMetrics() metricsSnapshot {
	snapMu.Lock()
	defer snapMu.Unlock()
	if !snapAt.IsZero() && time.Since(snapAt) < snapTTL {
		return snapLast
	}
	snapLast = collectMetrics()
	snapAt = time.Now()
	return snapLast
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cachedMetrics())
}

// How long apiListenAddr polls for the LAN bridge address before giving up.
// The autostart hook (debug_start.sh) starts this binary very early in
// boot -- before 1.sdk_init.sh has configured br0 -- so the bridge address
// legitimately isn't there yet at startup. On-device testing confirmed this
// is real, not theoretical: a first version that checked only once fell
// back to loopback and stayed unreachable for the rest of that boot. Poll
// instead of failing fast once.
const (
	apiListenRetryFor = 90 * time.Second
	apiListenPollEvery = 1 * time.Second
)

// lanIPv4 returns the first up interface's IPv4 address matching `want`
// (an exact interface name), or any "br*" interface if `want` is empty.
// Returns "" if none is found right now -- the caller decides whether and
// how long to retry.
func lanIPv4(want string) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		if want != "" && ifc.Name != want {
			continue
		}
		if want == "" && !strings.HasPrefix(ifc.Name, "br") {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if v4 := ipn.IP.To4(); v4 != nil {
					return v4.String()
				}
			}
		}
	}
	return ""
}

// apiListenAddr resolves the address to bind to. This runs inside the
// goroutine startAPIServer already spawns, so blocking here while polling
// never delays the stdio MCP loop in main() -- see startAPIServer's own
// comment.
func apiListenAddr() string {
	if addr := os.Getenv("API_ADDR"); addr != "" {
		return addr
	}
	port := os.Getenv("API_PORT")
	if port == "" {
		port = apiDefaultPort
	}
	want := os.Getenv("API_IFACE")

	deadline := time.Now().Add(apiListenRetryFor)
	for {
		if ip := lanIPv4(want); ip != "" {
			return net.JoinHostPort(ip, port)
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(apiListenPollEvery)
	}
	log.Printf("api: no LAN bridge IPv4 found after %s, binding loopback only", apiListenRetryFor)
	return net.JoinHostPort("127.0.0.1", port)
}

// startAPIServer runs the HTTP server in the background. It never blocks
// the stdio MCP loop in main(), and a bind failure (e.g. port already used,
// or the LAN IP not present yet at boot) is logged to stderr, not fatal --
// the MCP server over stdio is the primary interface and must keep working
// even if this API can't bind.
//
// addrReady, if non-nil, receives the address once resolved (used by
// startMDNS to advertise the same address once it's actually bound,
// without a second independent poll). Sending on it must not block the
// caller of startAPIServer -- see the buffered channel main() passes in.
func startAPIServer(addrReady chan<- string) {
	log.SetOutput(os.Stderr)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/metrics", metricsHandler)
	mux.HandleFunc("/api/tools", toolsHandler)
	mux.HandleFunc("/api/tools/", toolsHandler)

	go func() {
		// apiListenAddr can block for up to apiListenRetryFor (fresh boot,
		// waiting for br0). That's fine here -- this goroutine is not the
		// stdio loop in main(), which must stay responsive regardless.
		addr := apiListenAddr()
		setAPIAddr(addr)
		if addrReady != nil {
			addrReady <- addr
		}
		// Explicit timeouts and a header cap: a slow or stalled LAN client must not be able to
		// hold connections open on a device with this little memory.
		srv := &http.Server{
			Addr:              addr,
			Handler:           hostGuard(mux),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      20 * time.Second,
			IdleTimeout:       30 * time.Second,
			MaxHeaderBytes:    8 << 10,
		}
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("api: failed to listen on %s: %v", addr, err)
		}
	}()
}
