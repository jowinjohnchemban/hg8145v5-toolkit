# API reference

The resident service on the modem exposes the same tools two ways, through one shared function, so
they cannot behave differently:

- **MCP over stdio** (JSON-RPC 2.0, `tools/list` and `tools/call`), for MCP clients.
- **HTTP** on the LAN, for everything else.

Source: `main.go` (tools), `metrics.go` and `sysextra.go` (data), `actions.go` and `filter.go` (writes),
`httpapi.go` (HTTP). This file documents the wire format; it is not live data from the device.

## Binding

Resolved at startup, never hardcoded. Binds to the first IPv4 address of the LAN bridge interface
(first up interface named `br*`, or the one named by `API_IFACE`), not `0.0.0.0`, so it is reachable
from the LAN/Wi-Fi like the stock admin GUI without opening a port on the WAN interface. When
started by the autostart hook this runs before `br0` has an IP, so it polls for up to 90s before
falling back to `127.0.0.1`. `API_PORT` changes the port (default `8099`). `API_ADDR` overrides
everything; use it only after confirming that port is not reachable from the WAN side.

## Tools

| Tool | Kind | What it returns |
|---|---|---|
| `all_metrics` | read | Everything below in one snapshot |
| `system_info` | read | Kernel, uptime, load, CPU busy %, memory |
| `network_interfaces` | read | Per-interface up/down and counters |
| `wifi_clients_count` | read | Per-radio state and associated-client count |
| `voice_registration` | read | SIP registration status and recent abnormalities |
| `storage` | read | Total/free space per real filesystem |
| `connections` | read | Tracked connections vs limit, LAN neighbours seen |
| `service_info` | read | This service's version, PID, start time, bound address |
| `dns_filter` | read | DNS filter state and counters (see [dns-filter.md](dns-filter.md)) |
| `dns_filter_check` | read-only, POST | Would this domain be blocked, and why? |
| `dns_filter_pause` | **write** | Pause DNS blocking for up to an hour |
| `dns_filter_update` | **write** | Re-download the block lists now |
| `wifi_kick_client` | **write** | Deauthenticate one Wi-Fi client |
| `reboot_modem` | **write** | Reboot the modem |

Read tools share one snapshot cached for 2 seconds, so a burst of calls costs one collection.

## HTTP endpoints

| Request | Does |
|---|---|
| `GET /api/tools` | The tool list, same definitions MCP serves |
| `GET /api/tools/<name>` | Run a read tool, JSON result |
| `POST /api/tools/<name>` | Run a write tool; JSON body is the tool's arguments |
| `GET /api/metrics` | Full snapshot (same as `all_metrics`) |

Errors are `{"error": "..."}` with a matching status: 404 unknown tool, 405 wrong method (read tools
are GET-only, write tools POST-only), 400 invalid arguments or a refused action, 403/415/429/401 for
the write guards below.

```
curl http://<modem>:8099/api/tools/storage
curl -X POST -H 'Content-Type: application/json' \
     -d '{"interface":"vap0","mac":"aa:bb:cc:dd:ee:ff"}' \
     http://<modem>:8099/api/tools/wifi_kick_client
```

## Write actions

Small, narrow, reversible, and built on credential-free local tools. Nothing edits an OEM file or
stored configuration. Every attempt, allowed or refused, is logged to `actions.log` beside the
binary.

- **`wifi_kick_client`** `{interface, mac}`: deauthenticates one client through `hostapd_cli`. The
  interface must be a radio listed by `wifi_clients_count` and the MAC must be well-formed. The
  client may reconnect immediately; nothing persistent changes.
- **`reboot_modem`** `{confirm, delay_seconds?}`: restarts the modem, about 3 minutes with no
  internet, Wi-Fi or phone. Refused unless `confirm` is exactly `REBOOT`, refused if the modem
  booted less than 3 minutes ago (boot-loop guard), only one reboot can be pending, and
  `delay_seconds` is clamped to 5 to 300 (default 10).

### HTTP write guards

There is deliberately no stored password. The guards are structural, aimed at the realistic threat,
a web page open in a browser on the LAN trying to make that browser call the device:

- POST only, `Content-Type: application/json` required (a cross-site form cannot send it, and a
  cross-site script would need a CORS preflight, which this server never grants).
- Any request with an `Origin` header is refused for writes. Browsers add it, API clients do not.
- The `Host` header must be an IP or a `.local` name (blocks DNS rebinding). Applies to reads too.
- Writes are rate limited to one per 3 seconds.
- Optional: `API_WRITES=off` disables HTTP writes entirely; `API_WRITE_TOKEN`, if set, must be sent
  as `Authorization: Bearer <token>`.

**What this does not stop:** another device on the LAN that speaks HTTP can still call the write
endpoints. That is inherent to unauthenticated LAN access. Set `API_WRITES=off` if you do not want
it. The stdio MCP interface is not reachable from the network at all.

## Data

Privacy rule throughout: no IP address, hostname, SSID, or process command line is ever
returned. Ports are listed without the addresses they are bound to; processes by name and memory only.

### `system_info`

| Field | Type | Description |
|---|---|---|
| `kernel` | string | `/proc/version`, verbatim |
| `uptime_seconds` | number | Seconds since boot |
| `load1` / `load5` / `load15` | number | Load averages |
| `procs_running` / `procs_total` | integer | Process counts |
| `mem_total_kb` / `mem_free_kb` / `mem_cached_kb` / `mem_buffers_kb` | integer | From `/proc/meminfo` |
| `cpu_busy_percent` | number | CPU use over a 200ms sample (not an average since boot) |
| `go_runtime` | string | Go version and target of the binary |

### `storage[]`

`mount`, `fstype`, `total_kb`, `free_kb` for each real filesystem (ubifs, jffs2, squashfs, tmpfs...).
Free space on `/mnt/jffs2` is the number that limits what can be installed.

### `network_interfaces` (`ifaces[]`)

`name`, `up`, and cumulative `rx_`/`tx_` `bytes`, `packets`, `errs`, `drop`. Idle interfaces (zero rx
and tx bytes) are omitted. Compute rates client-side from two snapshots.

### `wifi_clients_count` (`wifi_clients[]`)

`interface`, `state` (hostapd's own, e.g. `ENABLED`), `clients` (associated station count), and
`error` if that radio could not be queried. Radios are discovered from `/var/run/hostapd-*/`.

### `voice_registration`

`ok` (true if no recent SIP registration abnormality), `detail`, and `recent_abnormalities` (up to
the last 10 log lines, e.g. SIP 403/408).

### `connections`

`conntrack_count`, `conntrack_max`, and `lan_neighbors_recently_seen` (hosts in the ARP cache on the
LAN bridge; entries age out, so this is not a live device count).

### `listening_tcp_ports` and `top_processes`

Sorted listening TCP port numbers, and the 10 processes using the most resident memory
(`name`, `rss_kb`).

### `service_info` (`service`)

`version`, `pid`, `started_unix`, `uptime_seconds`, `api_addr`, `http_writes_enabled`.

## What is not exposed, and why

The vendor's `display ...` commands (optical power, PON statistics, DHCP leases, board temperatures)
live inside the console daemon (`clid`), which needs a login even over loopback, and the matching
`/proc/wap_proc/*` files are binary structures. Reaching them would mean storing a password on the
device, so they are left out. There are no thermal sensors in sysfs on this firmware.

## Example (`all_metrics`, illustrative)

```json
{
  "time_unix": 1732262400,
  "system": { "uptime_seconds": 418203.1, "load1": 0.08, "cpu_busy_percent": 6.5,
              "mem_total_kb": 244696, "mem_free_kb": 86248, "go_runtime": "go1.21 on linux/arm" },
  "storage": [ { "mount": "/mnt/jffs2", "fstype": "ubifs", "total_kb": 26032, "free_kb": 17084 } ],
  "ifaces": [ { "name": "br0", "up": true, "rx_bytes": 918234112, "tx_bytes": 2203981823 } ],
  "wifi_clients": [ { "interface": "vap0", "state": "ENABLED", "clients": 2 } ],
  "voice_registration": { "ok": false, "detail": "recent registration abnormalities logged" },
  "connections": { "conntrack_count": 135, "conntrack_max": 16000, "lan_neighbors_recently_seen": 4 },
  "listening_tcp_ports": [ 22, 23, 53, 80, 8099 ],
  "top_processes": [ { "name": "ssmp", "rss_kb": 31820 } ],
  "service": { "version": "0.2.0", "api_addr": "<lan-address>:8099", "http_writes_enabled": true }
}
```

Values are placeholders except the shapes. Fields are trimmed here for readability.
