module hg8145v5-mcp

go 1.21

// hashicorp/mdns: pure Go, no cgo -- required for CGO_ENABLED=0 static
// builds (see docs/architecture.md, "Why Go"). Used for LAN-only
// service advertisement; see mdns.go.
require github.com/hashicorp/mdns v1.0.5
