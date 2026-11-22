// mdns.go advertises this device on the LAN via mDNS/Zeroconf (RFC 6762),
// so a hub, script, or tool on the LAN (Home Assistant, Node-RED, a plain
// `avahi-browse`/`dns-sd` command, anything that can browse mDNS) can find
// this device's API without the device's LAN IP being hardcoded anywhere.
//
// This is deliberately generic rather than hub-specific: it advertises a
// custom service type and a TXT record pointing at the HTTP API path,
// instead of emulating any particular vendor's device protocol. Turning
// this into actual entities inside a specific hub still needs a small bit
// of glue on that hub's side (e.g. a Home Assistant RESTful sensor) --
// mDNS only removes the need to hardcode an IP address here, it can't make
// every hub understand this device's JSON schema automatically.
//
// LAN-only by construction, not just by configuration: mDNS multicast
// packets carry IP TTL 1 (RFC 6762 section 3), so they are never routed across
// the WAN gateway hop regardless of what this code does.
package main

import (
	"log"
	"net"
	"strconv"

	"github.com/hashicorp/mdns"
)

const (
	mdnsServiceType = "_hg8145v5-mcp._tcp"
	mdnsInstance    = "HG8145V5 MCP"
)

// startMDNS advertises the API at apiAddr (host:port, as already resolved
// and bound by startAPIServer) over mDNS. It's meant to be called from its
// own goroutine (main() reads apiAddr off a channel first, which is why
// this function itself does not spawn one) -- it never blocks the stdio
// loop either way. A failure here -- no LAN IP, no multicast route -- is
// logged and otherwise harmless: the HTTP API itself works identically
// whether or not anything is listening for this announcement.
func startMDNS(apiAddr string) {
	host, portStr, err := net.SplitHostPort(apiAddr)
	if err != nil {
		log.Printf("mdns: could not parse API address %q: %v", apiAddr, err)
		return
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() {
		// Nothing useful to advertise if the API itself fell back to
		// loopback-only (see apiListenAddr) -- advertising 127.0.0.1
		// would only mislead anything browsing from elsewhere on the LAN.
		log.Printf("mdns: API bound to %q, not a LAN address -- skipping advertisement", apiAddr)
		return
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Printf("mdns: could not parse port %q: %v", portStr, err)
		return
	}

	service, err := mdns.NewMDNSService(
		mdnsInstance,
		mdnsServiceType,
		"",           // domain: default "local."
		"",           // hostName: let the library derive one
		port,
		[]net.IP{ip}, // advertise exactly the LAN address we're bound to
		[]string{"path=/api/metrics"},
	)
	if err != nil {
		log.Printf("mdns: could not create service record: %v", err)
		return
	}

	if _, err := mdns.NewServer(&mdns.Config{Zone: service}); err != nil {
		log.Printf("mdns: could not start responder: %v", err)
		return
	}
	log.Printf("mdns: advertising %s on %s:%d (service %s)", mdnsInstance, ip, port, mdnsServiceType)
}
