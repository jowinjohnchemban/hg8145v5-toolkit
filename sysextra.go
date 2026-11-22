// sysextra.go collects the remaining read-only data points: CPU load right
// now, filesystem space, connection counts, listening ports, the biggest
// processes, and this service's own details. Every source is a plain read of
// /proc or a filesystem stat -- no console login, no stored credential, and
// no exec -- so each of these is safe to poll and cannot change device state.
//
// Deliberate privacy rule, same as the rest of the API: nothing here returns
// an IP address, MAC address, hostname, SSID, or process command line. Ports
// are listed without the addresses they are bound to, and processes by name
// and memory only (command lines can carry secrets).
package main

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var serviceStarted = time.Now()

// The bound API address is resolved asynchronously at boot (see
// apiListenAddr), so it is published here once known for service_info.
var (
	apiAddrMu    sync.Mutex
	apiAddrBound string
)

func setAPIAddr(a string) {
	apiAddrMu.Lock()
	apiAddrBound = a
	apiAddrMu.Unlock()
}

func currentAPIAddr() string {
	apiAddrMu.Lock()
	defer apiAddrMu.Unlock()
	return apiAddrBound
}

type storageFS struct {
	Mount   string `json:"mount"`
	FSType  string `json:"fstype"`
	TotalKB uint64 `json:"total_kb"`
	FreeKB  uint64 `json:"free_kb"`
}

type connectionsInfo struct {
	ConntrackCount int `json:"conntrack_count"`
	ConntrackMax   int `json:"conntrack_max"`
	// LANNeighbors is how many LAN-side hosts are in the ARP cache. It is
	// "recently seen", not "currently connected": entries age out on their own.
	LANNeighbors int `json:"lan_neighbors_recently_seen"`
}

type processInfo struct {
	Name  string `json:"name"`
	RSSKB uint64 `json:"rss_kb"`
}

type serviceInfo struct {
	Version           string  `json:"version"`
	PID               int     `json:"pid"`
	StartedUnix       int64   `json:"started_unix"`
	UptimeSeconds     float64 `json:"uptime_seconds"`
	APIAddr           string  `json:"api_addr"`
	HTTPWritesEnabled bool    `json:"http_writes_enabled"`
}

func collectServiceInfo() serviceInfo {
	return serviceInfo{
		Version:           serverVersion,
		PID:               os.Getpid(),
		StartedUnix:       serviceStarted.Unix(),
		UptimeSeconds:     time.Since(serviceStarted).Seconds(),
		APIAddr:           currentAPIAddr(),
		HTTPWritesEnabled: httpWritesEnabled(),
	}
}

// readCPUTimes returns cumulative busy and total CPU jiffies from the
// aggregate "cpu" line of /proc/stat. Idle includes iowait, so time spent
// waiting on flash does not count as the CPU being busy.
func readCPUTimes() (busy, total uint64, ok bool) {
	raw, err := readFile("/proc/stat")
	if err != nil {
		return 0, 0, false
	}
	for _, line := range strings.Split(raw, "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		var vals []uint64
		for _, s := range strings.Fields(line)[1:] {
			v, _ := strconv.ParseUint(s, 10, 64)
			vals = append(vals, v)
		}
		if len(vals) < 4 {
			return 0, 0, false
		}
		for _, v := range vals {
			total += v
		}
		idle := vals[3]
		if len(vals) > 4 {
			idle += vals[4]
		}
		return total - idle, total, true
	}
	return 0, 0, false
}

// collectCPUBusyPercent measures CPU use over a 200ms window. A single
// reading of /proc/stat only gives an average since boot, which hides what
// the CPU is doing now; the short sample costs one cache miss 200ms.
func collectCPUBusyPercent() float64 {
	b1, t1, ok1 := readCPUTimes()
	time.Sleep(200 * time.Millisecond)
	b2, t2, ok2 := readCPUTimes()
	if !ok1 || !ok2 || t2 <= t1 {
		return 0
	}
	return float64(b2-b1) * 100 / float64(t2-t1)
}

// Only real filesystems are reported; proc, sysfs, devpts, cgroups and the
// like have no meaningful "free space".
var realFS = map[string]bool{
	"ubifs": true, "jffs2": true, "squashfs": true, "tmpfs": true,
	"ext2": true, "ext3": true, "ext4": true, "vfat": true,
}

func collectStorage() []storageFS {
	raw, err := readFile("/proc/mounts")
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []storageFS
	for _, line := range strings.Split(raw, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || !realFS[f[2]] || seen[f[1]] {
			continue
		}
		seen[f[1]] = true
		var st syscall.Statfs_t
		if err := syscall.Statfs(f[1], &st); err != nil {
			continue
		}
		bs := uint64(st.Bsize)
		out = append(out, storageFS{
			Mount:   f[1],
			FSType:  f[2],
			TotalKB: uint64(st.Blocks) * bs / 1024,
			FreeKB:  uint64(st.Bavail) * bs / 1024,
		})
	}
	return out
}

func readIntFile(path string) int {
	raw, err := readFile(path)
	if err != nil {
		return -1
	}
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return -1
	}
	return v
}

func collectConnections() connectionsInfo {
	c := connectionsInfo{
		ConntrackCount: readIntFile("/proc/sys/net/netfilter/nf_conntrack_count"),
		ConntrackMax:   readIntFile("/proc/sys/net/netfilter/nf_conntrack_max"),
	}
	if arp, err := readFile("/proc/net/arp"); err == nil {
		// Columns: IP, HW type, Flags, HW address, Mask, Device. Flags 0x0
		// is an incomplete entry (no reply); only bridge-side hosts count.
		for i, line := range strings.Split(arp, "\n") {
			f := strings.Fields(line)
			if i == 0 || len(f) < 6 {
				continue
			}
			if f[2] != "0x0" && strings.HasPrefix(f[5], "br") {
				c.LANNeighbors++
			}
		}
	}
	return c
}

// collectListeningPorts lists TCP ports in LISTEN state (kernel state 0A),
// IPv4 and IPv6 combined, without the addresses they are bound to.
func collectListeningPorts() []int {
	seen := map[int]bool{}
	for _, p := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		raw, err := readFile(p)
		if err != nil {
			continue
		}
		for i, line := range strings.Split(raw, "\n") {
			f := strings.Fields(line)
			if i == 0 || len(f) < 4 || f[3] != "0A" {
				continue
			}
			idx := strings.LastIndex(f[1], ":")
			if idx < 0 {
				continue
			}
			port, err := strconv.ParseUint(f[1][idx+1:], 16, 32)
			if err != nil {
				continue
			}
			seen[int(port)] = true
		}
	}
	ports := make([]int, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}

// collectTopProcesses returns the n processes using the most resident
// memory, by name only.
func collectTopProcesses(n int) []processInfo {
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	var procs []processInfo
	for _, d := range dirs {
		raw, err := readFile(d + "/status")
		if err != nil {
			continue
		}
		var p processInfo
		for _, line := range strings.Split(raw, "\n") {
			if v, ok := strings.CutPrefix(line, "Name:"); ok {
				p.Name = strings.TrimSpace(v)
			} else if v, ok := strings.CutPrefix(line, "VmRSS:"); ok {
				if f := strings.Fields(v); len(f) > 0 {
					p.RSSKB, _ = strconv.ParseUint(f[0], 10, 64)
				}
			}
		}
		if p.Name != "" && p.RSSKB > 0 {
			procs = append(procs, p)
		}
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].RSSKB > procs[j].RSSKB })
	if len(procs) > n {
		procs = procs[:n]
	}
	return procs
}
