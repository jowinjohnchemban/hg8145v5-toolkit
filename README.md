# hg8145v5-mcp

A small resident service for the Huawei **HG8145V5** GPON ONT. One static ARM binary gives the modem:

- **An MCP server** (stdio) and the **same tools over a LAN-only HTTP API**: system and CPU, memory,
  storage, interfaces, Wi-Fi clients, SIP registration, connections, and a few guarded actions.
- **A Pi-hole-style DNS ad and tracker filter** that can transparently cover every device on the LAN,
  over IPv4 and IPv6, and falls back to the modem's own resolver the moment it stops answering.
- **Home Assistant** integration through the HTTP API, with nothing leaving your network.

## Principles

- No stored credentials; every data source works without a login.
- No change to the vendor's files: it runs from `/mnt/jffs2` and a supported boot hook.
- LAN only. No cloud, no relay. The only outbound traffic is the optional block-list download.
- Fail open: an optional feature can never take the gateway's DNS, Wi-Fi or phone down.
- Private by design: no addresses, hostnames or queried domain names in responses or logs (the audit log records only the MAC you ask it to kick).

## Tools

| Tool | Kind |
|---|---|
| `all_metrics`, `system_info`, `network_interfaces`, `wifi_clients_count`, `voice_registration`, `storage`, `connections`, `service_info` | read |
| `dns_filter`, `dns_filter_check` | read |
| `wifi_kick_client`, `reboot_modem`, `dns_filter_pause`, `dns_filter_update` | guarded write |

Full reference: [docs/api.md](docs/api.md).

## Quick start

1. Download the `hg8145v5-mcp-arm5` artifact from CI (or build it, see [docs/install.md](docs/install.md)).
2. Copy it, `service.sh` and your `service.env` to `/mnt/jffs2/hg8145v5-mcp/` on the device and start it.
3. `curl http://<modem>:8099/api/tools/service_info`

For the DNS filter, copy [`service.env.example`](service.env.example) to `service.env`, set
`FILTER_TAKEOVER=on` and a list URL, and restart.

## Documentation

| Page | Contents |
|---|---|
| [docs/install.md](docs/install.md) | Build, install, autostart, uninstall |
| [docs/architecture.md](docs/architecture.md) | Components, device constraints, how autostart works |
| [docs/api.md](docs/api.md) | MCP and HTTP reference, data shapes |
| [docs/dns-filter.md](docs/dns-filter.md) | The DNS filter: lists, false-positive protection, failover |
| [docs/security.md](docs/security.md) | Threat model, write guards, limits |
| [docs/home-assistant.md](docs/home-assistant.md) | Home Assistant sensors and actions |
| [docs/testing.md](docs/testing.md) | What was verified on hardware, and what was not |

## Status

Version 0.2. Verified on one device (see [docs/testing.md](docs/testing.md)). Use it on hardware you own, take a
flash backup first, and read [docs/security.md](docs/security.md).
