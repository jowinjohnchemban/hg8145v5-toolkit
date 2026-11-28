package main

// filter.go -- optional DNS ad/tracker/malware filter (a small Pi-hole / uBlock-style
// network layer) built into this service.
//
// What it is: a DNS forwarder that answers blocked names with 0.0.0.0 / :: and passes
// everything else to the upstream resolver untouched. Only whole-domain rules can work
// at DNS level, so it understands hosts files and the domain subset of uBlock/ABP
// syntax ("||example.com^", "@@||example.com^" for allow). Cosmetic filters, URL-path
// rules and scriptlets need a browser and are ignored.
//
// Design rules (from the project's constraints):
//   - Off unless FILTER_TAKEOVER=on or FILTER_PORT is set. No list URL, address or credential is hardcoded;
//     FILTER_LISTS (comma-separated URLs) and FILTER_UPSTREAM come from the environment.
//   - Lists are downloaded outbound-only, parsed as a stream and kept ONLY IN RAM as
//     sorted 64-bit hashes (8 bytes per domain). Nothing is written to flash, so a
//     reboot costs one re-download and flash wear/space is zero.
//   - Fail open: if lists can't be fetched (offline, no TLS roots) nothing is blocked
//     and DNS keeps working; the previous in-RAM list is kept if a refresh fails.
//   - Privacy: counters only. Queried or blocked domain names are never logged or stored.
//   - Does not touch the OEM resolver on :53. It listens on its own local port, only answers
//     LAN clients, and (takeover.go) the LAN's port-53 traffic is redirected to it at runtime,
//     so no DHCP or GUI setting has to change and nothing address-specific is stored.

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	// Static Go binaries use the system CA store, which this firmware may not ship.
	// This registers an embedded fallback root set used only when the system has none.
	_ "golang.org/x/crypto/x509roots/fallback"
)

const (
	maxFilterDomains = 1_000_000 // 8 MB of hashes; hard cap against a hostile/huge list
	maxConcurrentDNS = 64
)

var (
	blockExact atomic.Pointer[[]uint64] // hosts-file / bare-domain entries: exact name only
	blockTree  atomic.Pointer[[]uint64] // "||domain^" rules: domain and all subdomains
	allowSet atomic.Pointer[[]uint64]

	fQueries, fBlocked atomic.Uint64

	// Pi-hole-style "disable blocking for N minutes". Unix seconds; 0 = not paused.
	// RAM only, so a restart always comes back with blocking on.
	pausedUntil atomic.Int64

	// FILTER_MODE=nxdomain answers blocked names with NXDOMAIN instead of 0.0.0.0
	// (Pi-hole's "NULL" vs "NXDOMAIN" blocking modes). Set once at startup.
	blockNX bool

	// Wakes the refresh loop early (dns_filter_update tool).
	refreshNow = make(chan struct{}, 1)

	fMu   sync.Mutex // guards the fields below
	fStat dnsFilterStats
)

// dnsFilterStats is what the dns_filter tool returns. No domain names, ever.
type dnsFilterStats struct {
	Enabled        bool   `json:"enabled"`
	Listen         string `json:"listen,omitempty"`
	Upstream       string `json:"upstream,omitempty"`
	Lists          int    `json:"lists_configured"`
	ListsLoaded    int    `json:"lists_loaded"`
	BlockedDomains int    `json:"blocked_domains"`
	AllowedDomains int    `json:"allowed_domains"`
	LastUpdateUnix int64  `json:"last_update_unix,omitempty"`
	LastError      string `json:"last_error,omitempty"`
	Queries        uint64 `json:"queries"`
	Blocked        uint64 `json:"blocked"`
	BlockedPercent float64 `json:"blocked_percent"`
	Mode           string `json:"mode,omitempty"`
	PausedUntil    int64  `json:"paused_until_unix,omitempty"`
}

func filterStats() dnsFilterStats {
	fMu.Lock()
	s := fStat
	fMu.Unlock()
	s.Queries, s.Blocked = fQueries.Load(), fBlocked.Load()
	if s.Queries > 0 {
		s.BlockedPercent = float64(s.Blocked) * 100 / float64(s.Queries)
	}
	if p := pausedUntil.Load(); p > time.Now().Unix() {
		s.PausedUntil = p
	}
	if s.Enabled { // resolved live: it follows WAN and LAN changes
		if u := upstreams(); len(u) > 0 {
			s.Upstream = u[0]
		}
	}
	return s
}

func setFilterStat(f func(*dnsFilterStats)) { fMu.Lock(); f(&fStat); fMu.Unlock() }

func hashName(s string) uint64 { h := fnv.New64a(); h.Write([]byte(s)); return h.Sum64() }

func inSet(p *[]uint64, h uint64) bool {
	if p == nil {
		return false
	}
	s := *p
	i := sort.Search(len(s), func(i int) bool { return s[i] >= h })
	return i < len(s) && s[i] == h
}

// protectedHosts are never filtered: the hosts the block lists are downloaded from, taken
// from FILTER_LISTS at startup, so a list can never cut off its own updates.
var protectedHosts atomic.Pointer[[]string]

// protectedName: special-use names (reverse lookups, local names, reserved test names)
// and the list hosts above are never blocked, whatever the lists or regexes say.
func protectedName(name string) bool {
	for _, suf := range []string{"arpa", "local", "localhost", "invalid", "test", "lan", "home"} {
		if name == suf || strings.HasSuffix(name, "."+suf) {
			return true
		}
	}
	if p := protectedHosts.Load(); p != nil {
		for _, h := range *p {
			if name == h || strings.HasSuffix(name, "."+h) {
				return true
			}
		}
	}
	return false
}

// explain decides whether a name is blocked and says why. regex=false limits the decision
// to the lists, which is what CNAME inspection uses so a loose regex can never cascade
// into blocking a legitimate site through an alias.
//
//   - A hosts-file or bare-domain entry matches that exact name only.
//   - A "||domain^" rule matches the domain and every subdomain.
//   - An allow entry on the name or any parent always wins over every block rule.
func explain(name string, regex bool) (blocked bool, reason string) {
	if protectedName(name) {
		return false, "protected name, never filtered"
	}
	exact, tree, alw := blockExact.Load(), blockTree.Load(), allowSet.Load()
	hit, first := "", true
	for n := name; n != ""; {
		h := hashName(n)
		if inSet(alw, h) {
			return false, "allowed by the allow list"
		}
		if hit == "" {
			if first && inSet(exact, h) {
				hit = "listed (exact name)"
			} else if inSet(tree, h) {
				hit = "listed (domain rule)"
			}
		}
		first = false
		i := strings.IndexByte(n, '.')
		if i < 0 {
			break
		}
		n = n[i+1:]
	}
	if regex && matchesRegex(allowRe.Load(), name) {
		return false, "allowed by an allow regex"
	}
	if hit != "" {
		return true, hit
	}
	if regex && matchesRegex(denyRe.Load(), name) {
		return true, "matches a deny regex"
	}
	return false, "not listed"
}

func matches(name string) bool { b, _ := explain(name, true); return b }

// toolDNSFilterCheck answers "would this name be blocked, and why?" for a name the user
// supplies. It exists to debug false positives; nothing is logged or stored.
func toolDNSFilterCheck(raw json.RawMessage) (string, error) {
	var a struct {
		Domain string `json:"domain"`
	}
	if err := json.Unmarshal(raw, &a); err != nil || strings.TrimSpace(a.Domain) == "" {
		return "", fmt.Errorf("provide {\"domain\": \"example.com\"}")
	}
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(a.Domain)), ".")
	b, why := explain(name, true)
	out, _ := json.Marshal(map[string]any{"domain": name, "blocked": b, "reason": why})
	return string(out), nil
}

// ---- list parsing ----------------------------------------------------------

func validDomain(d string) bool {
	if len(d) < 3 || len(d) > 253 || !strings.Contains(d, ".") {
		return false
	}
	for _, c := range d {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_') {
			return false
		}
	}
	return true
}

// parseLine returns a domain, whether it is an allow (exception) rule, and whether it covers
// the whole domain tree. Only the explicit uBlock/ABP form "||example.com^" is a tree rule.
// Hosts-file and bare-domain lines match that exact name only, as in Pi-hole, so a list
// entry for one host can never block unrelated subdomains of its parent.
func parseLine(line string) (domain string, allow, tree, ok bool) {
	line = strings.TrimSpace(strings.ToLower(line))
	if line == "" || line[0] == '#' || line[0] == '!' || line[0] == '[' {
		return
	}
	if i := strings.Index(line, " #"); i >= 0 { // trailing comment in hosts files
		line = strings.TrimSpace(line[:i])
	}
	// ABP / uBlock network rule, whole-domain form only: ||example.com^
	if strings.HasPrefix(line, "@@||") {
		allow, line = true, line[2:]
	}
	if strings.HasPrefix(line, "||") {
		line = line[2:]
		// uBlock's "$all" means "every request type", i.e. a plain block of the domain, which
		// is exactly what a DNS block is. Every other option (third-party, document-only,
		// per-site, redirects, badfilter, ...) narrows or changes the rule in a way DNS cannot
		// express, so those rules are skipped rather than widened. Exceptions never take options.
		if strings.HasSuffix(line, "^$all") && !allow {
			line = strings.TrimSuffix(line, "$all")
		}
		if !strings.HasSuffix(line, "^") { // path, wildcard or option rule: not DNS-expressible
			return
		}
		line = strings.TrimSuffix(line, "^")
		if validDomain(line) {
			return line, allow, true, true
		}
		return
	}
	f := strings.Fields(line)
	switch {
	case len(f) >= 2 && (f[0] == "0.0.0.0" || f[0] == "127.0.0.1"): // hosts format
		if validDomain(f[1]) {
			return f[1], false, false, true
		}
	case len(f) == 1 && validDomain(f[0]): // bare domain list
		return f[0], false, false, true
	}
	return
}

// listSets collects one refresh's rules before they are sorted and swapped in.
type listSets struct{ exact, tree, allow []uint64 }

func (s *listSets) add(d string, allow, tree bool) {
	h := hashName(d)
	switch {
	case allow:
		s.allow = append(s.allow, h) // an allow entry always covers its subdomains: safer
	case tree:
		if len(s.tree)+len(s.exact) < maxFilterDomains {
			s.tree = append(s.tree, h)
		}
	default:
		if len(s.tree)+len(s.exact) < maxFilterDomains {
			s.exact = append(s.exact, h)
		}
	}
}

// fetchList streams one list into the sets; nothing is buffered whole.
func fetchList(client *http.Client, url string, s *listSets) error {
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &httpStatusError{resp.StatusCode}
	}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 64<<20))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		if d, allow, tree, ok := parseLine(sc.Text()); ok {
			s.add(d, allow, tree)
		}
	}
	return sc.Err()
}

// readLocal appends rules from a local file. forceAllow makes every entry an allow rule.
// A missing file is fine (the feature is optional).
func readLocal(path string, s *listSets, forceAllow bool) {
	if path == "" {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(io.LimitReader(f, 4<<20))
	for sc.Scan() {
		if d, allow, tree, ok := parseLine(sc.Text()); ok {
			s.add(d, allow || forceAllow, tree)
		}
	}
}
// toolDNSFilterPause: Pi-hole's "disable blocking" button. seconds 0 resumes; max 1 hour,
// so a forgotten pause cannot leave the network unfiltered for long.
func toolDNSFilterPause(raw json.RawMessage) (string, error) {
	var a struct {
		Seconds int `json:"seconds"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return "", fmt.Errorf("invalid arguments: %w", err)
		}
	}
	if a.Seconds < 0 || a.Seconds > 3600 {
		return "", fmt.Errorf("seconds must be 0 (resume) to 3600")
	}
	if a.Seconds == 0 {
		pausedUntil.Store(0)
		auditAction("dns_filter_pause resumed")
		return "blocking resumed", nil
	}
	pausedUntil.Store(time.Now().Unix() + int64(a.Seconds))
	auditAction("dns_filter_pause seconds=%d", a.Seconds)
	return fmt.Sprintf("blocking paused for %d seconds", a.Seconds), nil
}

// toolDNSFilterUpdate: Pi-hole's "update gravity" -- re-download the lists now.
func toolDNSFilterUpdate(json.RawMessage) (string, error) {
	if !filterStats().Enabled {
		return "", fmt.Errorf("dns filter is not running")
	}
	select {
	case refreshNow <- struct{}{}:
		auditAction("dns_filter_update requested")
		return "list refresh requested", nil
	default:
		return "a refresh is already queued", nil
	}
}

type httpStatusError struct{ code int }

func (e *httpStatusError) Error() string { return "list server returned HTTP " + strconv.Itoa(e.code) }

func sortDedupe(s []uint64) []uint64 {
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// refreshLists rebuilds all sets from scratch and swaps them in atomically.
// If every list fails, the previous sets stay in place.
func refreshLists(urls []string) {
	client := &http.Client{Timeout: 90 * time.Second}
	var sets listSets
	loaded, lastErr := 0, ""
	for _, u := range urls {
		if err := fetchList(client, u, &sets); err != nil {
			// Report the failure but never the URL (it can embed a private token).
			lastErr = err.Error()
			continue
		}
		loaded++
	}
	// Local, user-managed lists (Pi-hole's custom deny / allow lists): one domain per
	// line, same syntax as the downloaded lists. Small, so flash cost is negligible.
	readLocal(os.Getenv("FILTER_DENY_FILE"), &sets, false)
	readLocal(os.Getenv("FILTER_ALLOW_FILE"), &sets, true)
	loadRegexLists() // FILTER_REGEX_DENY_FILE / FILTER_REGEX_ALLOW_FILE
	swap := loaded > 0 || len(urls) == 0
	if swap {
		exact, tree, allow := sortDedupe(sets.exact), sortDedupe(sets.tree), sortDedupe(sets.allow)
		blockExact.Store(&exact)
		blockTree.Store(&tree)
		allowSet.Store(&allow)
		sets = listSets{exact, tree, allow}
	}
	setFilterStat(func(s *dnsFilterStats) {
		s.ListsLoaded, s.LastError = loaded, lastErr
		if swap {
			s.BlockedDomains, s.AllowedDomains = len(sets.exact)+len(sets.tree), len(sets.allow)
			s.LastUpdateUnix = time.Now().Unix()
		}
	})
	auditAction("dns filter: refreshed, %d/%d lists, %d blocked domains", loaded, len(urls), len(sets.exact)+len(sets.tree))
}


// ---- DNS wire handling -----------------------------------------------------

// parseQuestion reads a single-question standard query. end is the offset just past
// the question section.
func parseQuestion(p []byte) (name string, qtype uint16, end int, ok bool) {
	if len(p) < 12 || p[2]&0x80 != 0 || (p[2]>>3)&0x0f != 0 || binary.BigEndian.Uint16(p[4:6]) != 1 {
		return
	}
	i := 12
	var b strings.Builder
	for {
		if i >= len(p) {
			return
		}
		l := int(p[i])
		if l == 0 {
			i++
			break
		}
		if l&0xc0 != 0 || i+1+l > len(p) { // compression pointers never appear in a question
			return
		}
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.Write(p[i+1 : i+1+l])
		i += 1 + l
	}
	if i+4 > len(p) {
		return
	}
	return strings.ToLower(b.String()), binary.BigEndian.Uint16(p[i : i+2]), i + 4, true
}

// blockedReply answers with 0.0.0.0 / :: for A / AAAA and an empty NOERROR for the rest.
func blockedReply(p []byte, qtype uint16, end int) []byte {
	r := make([]byte, end, end+28)
	copy(r, p[:end])
	r[2] = 0x80 | (p[2] & 0x01) // QR=1, keep RD
	r[3] = 0x80                 // RA=1, RCODE=0
	r[6], r[7], r[8], r[9], r[10], r[11] = 0, 0, 0, 0, 0, 0
	if blockNX {
		r[3] |= 3 // RCODE=3 NXDOMAIN, no answer section
		return r
	}
	var rdata int
	switch qtype {
	case 1:
		rdata = 4
	case 28:
		rdata = 16
	default:
		return r
	}
	r[7] = 1 // ANCOUNT
	r = append(r, 0xc0, 0x0c, byte(qtype>>8), byte(qtype), 0, 1, 0, 0, 0, 60, 0, byte(rdata))
	return append(r, make([]byte, rdata)...)
}

// decide returns a ready reply if the query must be blocked.
func decide(p []byte) (reply []byte, blocked bool) {
	name, qtype, end, ok := parseQuestion(p)
	fQueries.Add(1)
	if !ok || pausedUntil.Load() > time.Now().Unix() || !matches(name) {
		return nil, false
	}
	fBlocked.Add(1)
	return blockedReply(p, qtype, end), true
}

func serveUDP(pc net.PacketConn) {
	sem := make(chan struct{}, maxConcurrentDNS)
	buf := make([]byte, 4096)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if !clientAllowed(from) { // never act as an open resolver for the WAN side
			continue
		}
		pkt := append([]byte(nil), buf[:n]...)
		select {
		case sem <- struct{}{}:
		default:
			continue // shed load instead of piling up goroutines
		}
		go func() {
			defer func() { <-sem }()
			if r, blocked := decide(pkt); blocked {
				pc.WriteTo(r, from)
				return
			}
			if resp := forwardUDP(pkt); resp != nil {
				pc.WriteTo(inspectResponse(pkt, resp), from)
			}
		}()
	}
}

func serveTCP(ln net.Listener) {
	sem := make(chan struct{}, maxConcurrentDNS)
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		if !clientAllowed(c.RemoteAddr()) {
			c.Close()
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			c.Close()
			continue
		}
		go func() {
			defer func() { <-sem }()
			defer c.Close()
			c.SetDeadline(time.Now().Add(8 * time.Second))
			var lb [2]byte
			if _, err := io.ReadFull(c, lb[:]); err != nil {
				return
			}
			q := make([]byte, binary.BigEndian.Uint16(lb[:]))
			if _, err := io.ReadFull(c, q); err != nil {
				return
			}
			out := func(m []byte) {
				binary.BigEndian.PutUint16(lb[:], uint16(len(m)))
				c.Write(append(lb[:], m...))
			}
			if r, blocked := decide(q); blocked {
				out(r)
				return
			}
			if resp := forwardTCP(q); resp != nil {
				out(inspectResponse(q, resp))
			}
		}()
	}
}

// ---- startup ---------------------------------------------------------------

func startDNSFilter() {
	// Listens on a local port (not 53): the vendor resolver owns that. In transparent mode
	// the watcher redirects LAN port-53 traffic here. Empty = feature off.
	port := filterPort()
	if port == "" {
		return
	}
	addr := ":" + port // all addresses, so one socket serves IPv4 and IPv6; clientAllowed gates who
	var urls []string
	for _, u := range strings.Split(os.Getenv("FILTER_LISTS"), ",") {
		if u = strings.TrimSpace(u); u != "" {
			urls = append(urls, u)
		}
	}
	// The hosts the lists come from must never be filtered (derived from the settings).
	var hosts []string
	for _, u := range urls {
		if pu, err := neturl.Parse(u); err == nil && pu.Hostname() != "" {
			hosts = append(hosts, strings.ToLower(pu.Hostname()))
		}
	}
	protectedHosts.Store(&hosts)
	blockNX = strings.EqualFold(os.Getenv("FILTER_MODE"), "nxdomain")
	mode := "null"
	if blockNX {
		mode = "nxdomain"
	}
	setFilterStat(func(s *dnsFilterStats) { s.Enabled, s.Listen, s.Lists, s.Mode = true, addr, len(urls), mode })

	go func() {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			setFilterStat(func(s *dnsFilterStats) { s.Enabled, s.LastError = false, "cannot bind: "+err.Error() })
			auditAction("dns filter: cannot bind %s: %v", addr, err)
			return
		}
		go serveUDP(pc)
		if ln, err := net.Listen("tcp", addr); err == nil {
			go serveTCP(ln)
		}
		auditAction("dns filter: listening on %s", addr)
		if takeoverEnabled() {
			takeoverSignals() // the separate -dns-watch process owns install/removal
		}

		// Lists load after the listener is up, so DNS works (unfiltered) while they download.
		if len(urls) == 0 && os.Getenv("FILTER_DENY_FILE") == "" && os.Getenv("FILTER_REGEX_DENY_FILE") == "" {
			return
		}
		every := 24 * time.Hour
		if h, err := strconv.Atoi(os.Getenv("FILTER_REFRESH_HOURS")); err == nil && h > 0 {
			every = time.Duration(h) * time.Hour
		}
		time.Sleep(3 * time.Second) // let the listener and WAN settle; failed fetches retry quickly below
		for {
			refreshLists(urls)
			wait := every
			if filterStats().ListsLoaded == 0 {
				wait = 10 * time.Second // nothing loaded yet (e.g. WAN not up): retry fast, no fixed long wait
			}
			select {
			case <-time.After(wait):
			case <-refreshNow:
			}
		}
	}()
}
