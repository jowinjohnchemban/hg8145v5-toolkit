package main

// dnsnet.go -- address discovery and upstream forwarding for the DNS filter.
//
// Nothing here assumes a particular LAN address, subnet, WAN resolver or interface
// number: a GUI change to the LAN IP, a WAN reconnect that hands out new resolvers,
// or a renamed bridge is picked up at runtime instead of leaving a stale value.

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// defaultFilterPort is only a local port the filter listens on; clients never see it
// (the redirect maps port 53 to it). FILTER_PORT overrides it if it ever clashes.
const defaultFilterPort = "5335"

// filterPort is the local port the filter listens on, or "" when the feature is off
// (neither transparent mode nor an explicit FILTER_PORT is configured).
func filterPort() string {
	if p := os.Getenv("FILTER_PORT"); p != "" {
		return p
	}
	if takeoverEnabled() {
		return defaultFilterPort
	}
	return ""
}

// lanBridge returns the LAN bridge interface name and its IPv4 address: the first up
// interface called br* that has a non-link-local IPv4 (FILTER_IFACE overrides the name).
func lanBridge() (name, ip string) {
	want := os.Getenv("FILTER_IFACE")
	ifs, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 {
			continue
		}
		if want != "" {
			if i.Name != want {
				continue
			}
		} else if !strings.HasPrefix(i.Name, "br") {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLinkLocalUnicast() {
				return i.Name, n.IP.String()
			}
		}
	}
	return
}

// ---- who may use the filter -------------------------------------------------

var lanCache struct {
	sync.Mutex
	at   time.Time
	nets []*net.IPNet
}

// lanNets are the subnets (IPv4 and IPv6) of the LAN bridges, refreshed every 10s.
func lanNets() []*net.IPNet {
	lanCache.Lock()
	defer lanCache.Unlock()
	if lanCache.nets != nil && time.Since(lanCache.at) < 10*time.Second {
		return lanCache.nets
	}
	var nets []*net.IPNet
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if !strings.HasPrefix(i.Name, "br") {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				nets = append(nets, n)
			}
		}
	}
	lanCache.nets, lanCache.at = nets, time.Now()
	return nets
}

// clientAllowed is true only for local clients: loopback, link-local, private ranges or
// anything inside a LAN bridge subnet (which covers the ISP-assigned IPv6 prefix too).
// The filter listens on every address, so this is what stops it answering the WAN side.
func clientAllowed(a net.Addr) bool {
	var ip net.IP
	switch v := a.(type) {
	case *net.UDPAddr:
		ip = v.IP
	case *net.TCPAddr:
		ip = v.IP
	}
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() {
		return true
	}
	for _, n := range lanNets() {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ---- upstream resolvers -----------------------------------------------------

var upCache struct {
	sync.Mutex
	at   time.Time
	list []string
}

// upstreams returns the resolvers to forward to, best first, re-evaluated every 5s:
//  1. FILTER_UPSTREAM, if set;
//  2. otherwise the modem's own LAN resolver (its bridge address), i.e. the vendor's
//     dnsmasq, which always tracks the current WAN settings itself;
//  3. then the IPv4 nameservers in /etc/resolv.conf as a second chance.
//
// Our own queries leave through the OUTPUT path, which the port-53 redirect (PREROUTING)
// never touches, so asking the vendor resolver on port 53 cannot loop back to the filter.
func upstreams() []string {
	upCache.Lock()
	defer upCache.Unlock()
	if upCache.list != nil && time.Since(upCache.at) < 5*time.Second {
		return upCache.list
	}
	var l []string
	add := func(host string) {
		if host == "" {
			return
		}
		hp := net.JoinHostPort(host, "53")
		for _, e := range l {
			if e == hp {
				return
			}
		}
		l = append(l, hp)
	}
	if u := os.Getenv("FILTER_UPSTREAM"); u != "" {
		if h, _, err := net.SplitHostPort(u); err == nil {
			add(h)
		} else {
			add(u)
		}
	} else {
		_, lan := lanBridge()
		add(lan)
		if f, err := os.Open("/etc/resolv.conf"); err == nil {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				w := strings.Fields(sc.Text())
				if len(w) == 2 && w[0] == "nameserver" {
					if ip := net.ParseIP(w[1]); ip != nil && ip.To4() != nil {
						add(w[1])
					}
				}
			}
			f.Close()
		}
	}
	upCache.list, upCache.at = l, time.Now()
	return l
}

// forwardUDP sends the query to each upstream in turn and returns the first answer.
func forwardUDP(q []byte) []byte {
	for i, up := range upstreams() {
		if i >= 3 {
			break
		}
		c, err := net.DialTimeout("udp", up, time.Second)
		if err != nil {
			continue
		}
		c.SetDeadline(time.Now().Add(1500 * time.Millisecond))
		if _, err := c.Write(q); err == nil {
			buf := make([]byte, 4096)
			if n, err := c.Read(buf); err == nil {
				c.Close()
				return buf[:n]
			}
		}
		c.Close()
	}
	return nil
}

// forwardTCP does the same over TCP (length-prefixed messages).
func forwardTCP(q []byte) []byte {
	for i, up := range upstreams() {
		if i >= 3 {
			break
		}
		c, err := net.DialTimeout("tcp", up, time.Second)
		if err != nil {
			continue
		}
		c.SetDeadline(time.Now().Add(4 * time.Second))
		var lb [2]byte
		binary.BigEndian.PutUint16(lb[:], uint16(len(q)))
		if _, err := c.Write(append(lb[:], q...)); err == nil {
			if _, err := io.ReadFull(c, lb[:]); err == nil {
				resp := make([]byte, binary.BigEndian.Uint16(lb[:]))
				if _, err := io.ReadFull(c, resp); err == nil {
					c.Close()
					return resp
				}
			}
		}
		c.Close()
	}
	return nil
}
