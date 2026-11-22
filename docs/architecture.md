# Architecture

## What it is

One static Go binary, `hg8145v5-mcp`, that runs resident on a Huawei HG8145V5 ONT (a GPON home gateway).

```
                       +------------------------------------------+
 MCP client --stdio--> |  tools (main.go)                         |
 HTTP client --LAN---> |   reads : metrics.go, sysextra.go        |
                       |   writes: actions.go, filter.go          |
                       |  HTTP   : httpapi.go (guards)            |
 mDNS (mdns.go) <------|                                          |
                       |  DNS filter: filter.go dnsinspect.go     |
 LAN DNS :53 --redirect--> dnsnet.go                              |
        ^              +------------------------------------------+
        |
        +-- watcher (-dns-watch, takeover.go) probes the filter and owns the redirect
```

- **Tools.** One list of tools in `main.go` and one dispatch function. MCP (stdio) and HTTP both call it,
  so they cannot behave differently.
- **Data.** Plain reads of `/proc`, `statfs`, `hostapd_cli` and a vendor log script. No credentials and no
  vendor CLI session. Collected on demand and cached for 2 seconds.
- **Writes.** A short, named list of narrow actions (kick one Wi-Fi client, reboot, DNS filter pause and
  refresh), each audit-logged. See [security.md](security.md).
- **DNS filter.** Optional. See [dns-filter.md](dns-filter.md).
- **mDNS.** Advertises `_hg8145v5-mcp._tcp` on the LAN so clients can find the API.

## The device constraints that shape it

| Constraint | Consequence |
|---|---|
| Read-only squashfs root filesystem | Nothing under `/` can be edited. Only `/mnt/jffs2` (UBIFS) is writable. |
| Limited free flash (tens of MB) | One static binary of about 7.6 MB; block lists live in RAM, not flash. |
| About 244 MB RAM, shared with the gateway | Aggressive GC and a soft heap limit; the service uses a few MB at rest. |
| No Python, Node or package manager | Go, cross-compiled. |
| Kernel reports no VFP/NEON | `GOARM=5` (soft float). A `GOARM=7` build dies with SIGILL. |
| Minimal BusyBox (no `nohup`, `setsid`, `timeout`) | The supervisor script uses only plain `sh`. |
| Live internet, Wi-Fi and phone gateway | Nothing may block boot or the data path; every optional feature fails open. |

## Why Go

`CGO_ENABLED=0` gives a fully static binary with no dependency on the device's libc, and Go's
cross-compiler needs no device toolchain. The only module dependency is `hashicorp/mdns` (pure Go); the
build also embeds a fallback set of CA roots, because the firmware may not ship any.

## Resident service

- `service.sh start|stop|status` runs the binary directly under a respawn loop (`HG_NO_STDIO=1`, so the
  resident copy does not read stdin). After every exit it runs `hg8145v5-mcp -dns-cleanup`, then restarts.
  The binary must not be run as one half of a shell pipeline: the shell waits for the other half, so a
  crash would never be noticed.
- `status` checks that the PID file names a live process of ours, not just any process with that PID.
- Optional settings are read from `service.env` beside the script, which stays on the device.

## Autostart without touching the OEM files

The root filesystem cannot be edited, so autostart uses a hook the firmware itself provides:
`/mnt/jffs2/debug_start.sh` is run very early in boot by `1.sdk_init.sh`, which then renames it and exits.
On its own that would skip the rest of boot (drivers, voice, the management daemon).

`debug_start.sh` in this repo is a chained version of that hook:

1. Check that the real boot script exists and is runnable; if not, change nothing and let boot continue.
2. Guard against recursion, then start `service.sh`.
3. `exec` a fresh copy of the real boot script, so the vendor's "rename and exit" lines never run.
4. From a background subshell, restore itself about 30 seconds later so the next boot repeats the cycle.

Every step fails safe: if anything is unexpected, the hook steps aside and the device boots normally.

## Binding and discovery

The HTTP API binds to the first IPv4 address of the LAN bridge (the first up interface named `br*`,
overridable), not `0.0.0.0`, so it is reachable from the LAN without being open on the WAN side. At boot the
bridge has no address yet, so it waits up to 90 seconds before falling back to loopback.
