package main

// takeover.go -- optional transparent mode for the DNS filter (FILTER_TAKEOVER=on).
//
//	any LAN client -> port 53 --(local redirect)--> our filter --> modem's own resolver --> internet
//
// Every DNS query a LAN client sends on port 53 is redirected to the filter, over IPv4
// and IPv6 alike, whatever server the client asked for (the DHCP-assigned resolver, the
// modem's own address, a resolver hard-coded in the device itself). So it keeps working if the DHCP DNS
// setting, the LAN address or the WAN resolvers are changed in the stock GUI. The
// vendor's dnsmasq is left untouched and is simply the filter's upstream. Encrypted DNS
// (DoH/DoT) cannot be seen and is not touched.
//
// The redirect is a plain local-port REDIRECT, so no extra IP address is involved and
// nothing is keyed on a specific address: the LAN bridge is discovered at runtime
// (dnsnet.go), the rules carry a comment tag, and removal finds them by that tag, so rules
// left over from an earlier interface or port are still cleaned up.
//
// FAILOVER, like a load balancer's health check:
//   - A separate watcher process (`hg8145v5-mcp -dns-watch`, started by service.sh) owns
//     the redirect. Twice a second it sends a real query THROUGH the filter to the
//     upstream, so it tests the whole path, not just the socket.
//   - Three failed probes in a row (about 1.5s) delete the redirect and DNS goes straight
//     back to whatever resolver the client was using. When the filter process is simply
//     dead the probe is refused instantly, so failure is detected on the first probe.
//   - Two good probes install it again, and a healthy watcher re-checks it every 10s in
//     case the firmware rebuilt its firewall chains or the LAN bridge changed.
//   - The watcher is independent of the filter and of its supervisor, so it still works
//     if either dies in any way, including kill -9; service.sh respawns it if it exits.
//   - A clean stop (SIGTERM) also removes the redirect at once, and a reboot clears the
//     firewall, so the worst case is always bounded.
//
// The redirect is a runtime-only firewall rule: nothing persistent, nothing in OEM files.
// Our own upstream queries leave the modem through the OUTPUT path, which a PREROUTING
// rule never sees, so there is no forwarding loop.

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// ruleTag marks our rules so they can be found and removed without knowing any detail.
const ruleTag = "hg8145v5-dns"

// firewallTools: IPv4 first, then IPv6. A missing or failing IPv6 tool is tolerated.
var firewallTools = []string{"iptables", "ip6tables"}

func takeoverEnabled() bool { return strings.EqualFold(os.Getenv("FILTER_TAKEOVER"), "on") }

// ruleArgs builds the rule for one protocol; op is -I (insert) or -D (delete).
func ruleArgs(op, proto, iface, port string) []string {
	return []string{"-t", "nat", op, "PREROUTING", "-i", iface, "-p", proto, "--dport", "53",
		"-m", "comment", "--comment", ruleTag, "-j", "REDIRECT", "--to-ports", port}
}

func firewall(tool string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, tool, args...).Output()
}

// taggedRules lists our rules in one table family as `-S` prints them.
func taggedRules(tool string) []string {
	out, err := firewall(tool, "-t", "nat", "-S", "PREROUTING")
	if err != nil {
		return nil
	}
	var rules []string
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(l, ruleTag) {
			rules = append(rules, l)
		}
	}
	return rules
}

// removeTakeover deletes every rule carrying our tag, in both families; safe when none
// exist. It reports whether it removed anything. It never needs to know the interface or
// port the rules were created with.
func removeTakeover() bool {
	removed := false
	for _, tool := range firewallTools {
		for _, l := range taggedRules(tool) {
			f := strings.Fields(l) // "-A PREROUTING ..." -> "-D PREROUTING ..."
			if len(f) > 2 && f[0] == "-A" {
				if _, err := firewall(tool, append([]string{"-t", "nat", "-D"}, f[1:]...)...); err == nil {
					removed = true
				}
			}
		}
	}
	return removed
}

// ensureTakeover makes the installed rules exactly the wanted pair per family (one per
// protocol, right interface, right port), replacing anything else, and reports whether it
// changed anything.
func ensureTakeover(iface, port string) bool {
	changed := false
	for _, tool := range firewallTools {
		rules := taggedRules(tool)
		have := map[string]bool{}
		for _, l := range rules {
			for _, proto := range []string{"udp", "tcp"} {
				if strings.Contains(l, " -p "+proto+" ") && strings.Contains(l, " -i "+iface+" ") &&
					strings.HasSuffix(l, " --to-ports "+port) {
					have[proto] = true
				}
			}
		}
		if have["udp"] && have["tcp"] && len(rules) == 2 {
			continue
		}
		// Wrong or partial set: drop this family's rules and write the right pair.
		for _, l := range rules {
			if f := strings.Fields(l); len(f) > 2 && f[0] == "-A" {
				firewall(tool, append([]string{"-t", "nat", "-D"}, f[1:]...)...)
			}
		}
		for _, proto := range []string{"udp", "tcp"} {
			if _, err := firewall(tool, ruleArgs("-I", proto, iface, port)...); err == nil {
				changed = true
			}
		}
	}
	return changed
}

// probeThroughFilter sends one real query (the root name servers, which any working
// resolver answers) to the filter and expects it to be forwarded and answered. Any DNS
// reply counts, including an error code from upstream: the path itself works.
func probeThroughFilter(port string, timeout time.Duration) bool {
	q := make([]byte, 12, 32)
	binary.BigEndian.PutUint16(q[0:], 0xBEEF)
	q[2] = 0x01 // RD
	q[5] = 1    // QDCOUNT
	q = append(q, 0, 0, 2, 0, 1) // root name, NS, IN

	c, err := net.DialTimeout("udp", net.JoinHostPort("127.0.0.1", port), timeout)
	if err != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write(q); err != nil {
		return false
	}
	resp := make([]byte, 1500)
	n, err := c.Read(resp)
	return err == nil && n >= 12 && resp[0] == 0xBE && resp[1] == 0xEF && resp[2]&0x80 != 0
}

// takeoverSignals runs inside the filter process: a clean stop removes the redirect at
// once instead of leaving it for the watcher to notice.
func takeoverSignals() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() { <-sig; removeTakeover(); os.Exit(0) }()
}

// dnsWatch is the watcher process (`hg8145v5-mcp -dns-watch`): it alone installs and
// removes the redirect, based on whether the filter really answers.
func dnsWatch() {
	if !takeoverEnabled() {
		return
	}
	removeTakeover() // start from a known state

	const (
		tick       = 500 * time.Millisecond
		probeLimit = 700 * time.Millisecond
	)
	installed, bad, good, sinceCheck := false, 0, 0, 0
	for ; ; time.Sleep(tick) {
		port := filterPort()
		iface, _ := lanBridge()
		if port != "" && iface != "" && probeThroughFilter(port, probeLimit) {
			bad, good = 0, good+1
			if !installed && good >= 2 {
				if ensureTakeover(iface, port) {
					auditAction("dns takeover: redirect installed on %s", iface)
				}
				installed, sinceCheck = true, 0
			} else if installed {
				if sinceCheck++; sinceCheck >= 20 { // ~10s: survive firewall rebuilds / bridge changes
					if ensureTakeover(iface, port) {
						auditAction("dns takeover: redirect re-applied after a firewall or LAN change")
					}
					sinceCheck = 0
				}
			}
			continue
		}
		good = 0
		if bad++; bad == 3 && installed {
			removeTakeover()
			installed = false
			auditAction("dns takeover: filter not answering, redirect removed (clients use their own resolver again)")
		}
	}
}
