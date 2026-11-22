package main

// dnsinspect.go -- two Pi-hole-style checks on top of the exact-domain lists in filter.go:
//
//  1. Regex deny / allow lists, from local files (FILTER_REGEX_DENY_FILE and
//     FILTER_REGEX_ALLOW_FILE, one expression per line, '#' comments). They are matched
//     against the full queried name. Small, user-managed, never downloaded.
//
//  2. Deep CNAME inspection. Trackers often hide behind a harmless-looking first-party
//     name that is only an alias (CNAME) for the tracker's domain. The query name itself
//     passes the lists, so after the upstream answers, every CNAME target in the answer is
//     checked as well, and the whole answer is replaced by the blocked reply if any target
//     is listed. Only the names inside the answer are examined; nothing is stored or logged.

import (
	"bufio"
	"encoding/binary"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

var denyRe, allowRe atomic.Pointer[[]*regexp.Regexp]

func matchesRegex(p *[]*regexp.Regexp, name string) bool {
	if p == nil {
		return false
	}
	for _, re := range *p {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

// loadRegexFile compiles one file; bad lines are skipped so one typo cannot disable the rest.
func loadRegexFile(path string) *[]*regexp.Regexp {
	var res []*regexp.Regexp
	if path != "" {
		if f, err := os.Open(path); err == nil {
			sc := bufio.NewScanner(f)
			for sc.Scan() && len(res) < 2000 {
				l := strings.TrimSpace(sc.Text())
				if l == "" || l[0] == '#' {
					continue
				}
				if re, err := regexp.Compile("(?i)" + l); err == nil {
					res = append(res, re)
				}
			}
			f.Close()
		}
	}
	return &res
}

func loadRegexLists() {
	denyRe.Store(loadRegexFile(os.Getenv("FILTER_REGEX_DENY_FILE")))
	allowRe.Store(loadRegexFile(os.Getenv("FILTER_REGEX_ALLOW_FILE")))
}

// ---- CNAME inspection -------------------------------------------------------

// skipName returns the offset just past a (possibly compressed) name, or -1.
func skipName(m []byte, off int) int {
	for off < len(m) {
		l := int(m[off])
		switch {
		case l == 0:
			return off + 1
		case l&0xc0 == 0xc0:
			return off + 2
		default:
			off += 1 + l
		}
	}
	return -1
}

// readName decodes a name, following compression pointers (bounded, so a malicious
// loop cannot hang it).
func readName(m []byte, off int) (string, bool) {
	var b strings.Builder
	for jumps := 0; off >= 0 && off < len(m); {
		l := int(m[off])
		switch {
		case l == 0:
			return strings.ToLower(b.String()), true
		case l&0xc0 == 0xc0:
			if off+1 >= len(m) || jumps > 10 {
				return "", false
			}
			off = (l&0x3f)<<8 | int(m[off+1])
			jumps++
		default:
			if off+1+l > len(m) {
				return "", false
			}
			if b.Len() > 0 {
				b.WriteByte('.')
			}
			b.Write(m[off+1 : off+1+l])
			off += 1 + l
		}
	}
	return "", false
}

// cnameBlocked reports whether any CNAME target in a successful answer is on the lists.
func cnameBlocked(resp []byte) bool {
	if len(resp) < 12 || resp[3]&0x0f != 0 { // only NOERROR answers carry CNAME chains
		return false
	}
	qd := int(binary.BigEndian.Uint16(resp[4:6]))
	an := int(binary.BigEndian.Uint16(resp[6:8]))
	off := 12
	for i := 0; i < qd; i++ {
		if off = skipName(resp, off); off < 0 {
			return false
		}
		off += 4
	}
	for i := 0; i < an && off > 0 && off < len(resp); i++ {
		if off = skipName(resp, off); off < 0 || off+10 > len(resp) {
			return false
		}
		typ := binary.BigEndian.Uint16(resp[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(resp[off+8 : off+10]))
		off += 10
		if off+rdlen > len(resp) {
			return false
		}
		if typ == 5 { // CNAME: rdata is the target name
			if target, ok := readName(resp, off); ok {
				if blocked, _ := explain(target, false); blocked { // lists only, never regexes
					return true
				}
			}
		}
		off += rdlen
	}
	return false
}

// inspectResponse returns the blocked reply in place of resp when a CNAME target is listed,
// otherwise resp unchanged. Blocking paused by the user is respected.
func inspectResponse(query, resp []byte) []byte {
	if pausedUntil.Load() > time.Now().Unix() || !cnameBlocked(resp) {
		return resp
	}
	if name, qtype, end, ok := parseQuestion(query); ok {
		// A name the user explicitly allowed is never blocked because of what it aliases.
		if blocked, why := explain(name, true); !blocked && strings.HasPrefix(why, "allowed") {
			return resp
		}
		fBlocked.Add(1)
		return blockedReply(query, qtype, end)
	}
	return resp
}
