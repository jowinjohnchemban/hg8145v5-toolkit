package main

// portguard.go -- every port this service opens is reachable from the LAN only, by default.
//
// The vendor firewall already refuses SSH, Telnet and the web UI from the WAN side. This does the
// same for what we add: the HTTP API, the DNS filter and the mDNS responder. The code already
// refuses non-LAN clients (hostGuard, clientAllowed), but a service should not depend on its own
// code being the only barrier, so the firewall drops it first, as a second, independent layer.
//
// How, with the smallest possible footprint:
//
//	INPUT  --(one tagged jump per protocol and port, inserted first)-->  HG_GUARD
//	HG_GUARD:  -i lo -> RETURN,  -i br+ (and the discovered LAN bridge) -> RETURN,  everything else -> DROP
//
// "LAN-only" is a whitelist (loopback and the LAN bridge) rather than a list of WAN interface names,
// so a WAN interface called anything at all is covered, and so are IPv4 and IPv6 (both tools).
//
// The rules are runtime-only (a reboot clears them), tagged so they can be found and removed without
// knowing anything else, and re-asserted every guardEvery in case the firmware rebuilds its firewall.
// The chain is always built so that LAN traffic passes at every intermediate step: first the RETURN
// rules, last the DROP, so an update can never lock the LAN out. If no LAN bridge can be found the
// guard does nothing at all, rather than risk dropping traffic it cannot classify.
//
// PORT_GUARD=off disables it. Nothing here touches OEM files or vendor chains.

import (
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	guardTag   = "hg8145v5-guard"
	guardChain = "HG_GUARD"
	guardEvery = 15 * time.Second
	mdnsPort   = "5353"
)

// guardPort is one protocol/port pair to protect.
type guardPort struct{ proto, port string }

func guardEnabled() bool { return !strings.EqualFold(os.Getenv("PORT_GUARD"), "off") }

// apiPort is the TCP port the HTTP API listens on (API_ADDR wins, then API_PORT, then the default).
func apiPort() string {
	if addr := os.Getenv("API_ADDR"); addr != "" {
		if _, p, err := net.SplitHostPort(addr); err == nil && p != "" {
			return p
		}
	}
	if p := os.Getenv("API_PORT"); p != "" {
		return p
	}
	return apiDefaultPort
}

// vendorPorts are ports the stock firmware uses on this modem (SIP voice, UPnP, DHCP, its resolver,
// remote management and its internal services). The guard must never touch them, whatever the settings
// say: a mistyped FILTER_PORT or API_PORT must not be able to cut off voice, DHCP or the ISP's management.
var vendorPorts = map[string]bool{
	"53": true, "67": true, "68": true, "123": true, "161": true, "546": true, "547": true,
	"1900": true, "5060": true, "5061": true, "7547": true, "8080": true,
	"27998": true, "37215": true, "37225": true, "37443": true, "37444": true,
}

// guardable reports whether a port may be guarded: unprivileged (1024 and up) and not a vendor port.
func guardable(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1024 && n <= 65535 && !vendorPorts[port]
}

// guardedPorts lists every port this service listens on, given the current settings, minus anything
// that is not safe to guard (see vendorPorts).
func guardedPorts() []guardPort {
	var ports []guardPort
	if p := filterPort(); p != "" {
		ports = append(ports, guardPort{"udp", p}, guardPort{"tcp", p})
	}
	ports = append(ports, guardPort{"tcp", apiPort()}, guardPort{"udp", mdnsPort})
	safe := ports[:0]
	for _, gp := range ports {
		if guardable(gp.port) {
			safe = append(safe, gp)
		}
	}
	return safe
}

// guardChainRules returns the exact lines `-S HG_GUARD` prints for the wanted chain, in order:
// a RETURN per LAN interface, then the DROP. ensureGuard compares against this.
func guardChainRules(lan []string) []string {
	rules := make([]string, 0, len(lan)+1)
	for _, iface := range lan {
		rules = append(rules, "-A "+guardChain+" -i "+iface+" -j RETURN")
	}
	return append(rules, "-A "+guardChain+" -j DROP")
}

// guardLAN returns the interfaces allowed to reach guarded ports: loopback, every br* bridge, and the
// discovered LAN bridge if it is named differently. It returns nil when no LAN bridge is found.
func guardLAN() []string {
	name, _ := lanBridge()
	if name == "" {
		return nil
	}
	lan := []string{"lo", "br+"}
	if !strings.HasPrefix(name, "br") {
		lan = append(lan, name)
	}
	return lan
}

// guardJumpArgs builds the INPUT jump for one port; op is "-I" (insert at the top) or "-D".
func guardJumpArgs(op string, gp guardPort) []string {
	args := []string{op, "INPUT"}
	if op == "-I" {
		args = append(args, "1")
	}
	return append(args, "-p", gp.proto, "--dport", gp.port,
		"-m", "comment", "--comment", guardTag, "-j", guardChain)
}

// guardJumps lists our tagged jump rules in INPUT, as `-S` prints them.
func guardJumps(tool string) []string {
	out, err := firewall(tool, "-S", "INPUT")
	if err != nil {
		return nil
	}
	var rules []string
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(l, guardTag) {
			rules = append(rules, l)
		}
	}
	return rules
}

// guardChainLines returns the rules currently in our chain (without the "-N" line), or nil if the
// chain does not exist.
func guardChainLines(tool string) []string {
	out, err := firewall(tool, "-S", guardChain)
	if err != nil {
		return nil
	}
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.HasPrefix(l, "-A ") {
			lines = append(lines, strings.TrimSpace(l))
		}
	}
	return lines
}

func sameLines(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ensureGuard makes the firewall exactly the wanted guard for both IP families and reports whether it
// changed anything. A missing IPv6 tool is tolerated (the call just fails and that family is skipped).
func ensureGuard(ports []guardPort, lan []string) bool {
	changed := false
	wantChain := guardChainRules(lan)
	for _, tool := range firewallTools {
		if _, err := firewall(tool, "-S", "INPUT"); err != nil {
			continue // tool missing or the family unsupported
		}
		// 1. The chain first, so a jump never points at a missing or half-built chain. RETURNs are
		// appended before the DROP, so LAN traffic passes at every step.
		if !sameLines(guardChainLines(tool), wantChain) {
			firewall(tool, "-N", guardChain) // exists already is fine
			firewall(tool, "-F", guardChain)
			for _, rule := range wantChain {
				if f := strings.Fields(rule); len(f) > 1 {
					firewall(tool, f...)
				}
			}
			changed = true
		}
		// 2. The jumps: exactly one per wanted port, nothing else.
		have := guardJumps(tool)
		want := map[string]bool{}
		for _, gp := range ports {
			want[gp.proto+":"+gp.port] = true
		}
		ok := len(have) == len(want)
		for _, l := range have {
			found := false
			for key := range want {
				proto, port, _ := strings.Cut(key, ":")
				if strings.Contains(l, " -p "+proto+" ") && strings.Contains(l, " --dport "+port+" ") {
					found = true
				}
			}
			ok = ok && found
		}
		if ok {
			continue
		}
		for _, l := range have {
			if f := strings.Fields(l); len(f) > 2 && f[0] == "-A" {
				firewall(tool, append([]string{"-D"}, f[1:]...)...)
			}
		}
		for _, gp := range ports {
			if _, err := firewall(tool, guardJumpArgs("-I", gp)...); err == nil {
				changed = true
			}
		}
	}
	return changed
}

// removeGuard deletes our jumps and chain in both families; safe when none exist.
func removeGuard() bool {
	removed := false
	for _, tool := range firewallTools {
		for _, l := range guardJumps(tool) {
			if f := strings.Fields(l); len(f) > 2 && f[0] == "-A" {
				if _, err := firewall(tool, append([]string{"-D"}, f[1:]...)...); err == nil {
					removed = true
				}
			}
		}
		if _, err := firewall(tool, "-F", guardChain); err == nil {
			firewall(tool, "-X", guardChain)
			removed = true
		}
	}
	return removed
}

// startPortGuard applies the guard now and keeps it applied. It never blocks the caller. Only the
// resident service (HG_NO_STDIO=1, started by service.sh) manages the firewall: a short-lived process
// an MCP client starts over stdio must not touch it.
func startPortGuard() {
	if !guardEnabled() || os.Getenv("HG_NO_STDIO") != "1" {
		return
	}
	go func() {
		for first := true; ; first = false {
			if lan := guardLAN(); lan != nil {
				if ensureGuard(guardedPorts(), lan) {
					if first {
						auditAction("port guard: service ports restricted to the LAN")
					} else {
						auditAction("port guard: rules re-applied after a firewall change")
					}
				}
			}
			time.Sleep(guardEvery)
		}
	}()
}
