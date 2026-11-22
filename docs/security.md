# Security model

## Principles

- **No stored credentials.** The service never reads or writes a password. Every data source works without
  one (`/proc`, `statfs`, `hostapd_cli`). Optional secrets (`API_WRITE_TOKEN`) come from the environment of
  the running service and never from source or git.
- **No OEM modification.** Nothing in the vendor's read-only root filesystem or its generated configuration is
  edited. The service uses the supported debug hook, its own files in `/mnt/jffs2`, and runtime-only changes.
- **LAN only.** The API binds to the LAN bridge address, not the WAN. The DNS filter only answers LAN
  clients. Nothing is published to the internet and there is no cloud dependency; the only outbound
  traffic is the optional block-list download.
- **Privacy.** Responses and logs carry no IP address, MAC address, hostname, SSID, process command line
  or queried domain name. The DNS filter keeps counters only.
- **Fail open.** Optional features never block the gateway: if the filter or a list fails, DNS goes straight
  to the modem's own resolver.

## HTTP write guards

There is deliberately no stored password, so write protection is structural, aimed at the realistic threat: a
web page open in a browser on the LAN trying to make that browser call the device.

- POST only, `Content-Type: application/json` required.
- Any request with an `Origin` header is refused for writes (browsers add it; API clients do not).
- The `Host` header must be an IP address or a `.local` name (blocks DNS rebinding). Applies to reads too.
- Writes are rate limited to one per 3 seconds.
- Optional: `API_WRITES=off` disables HTTP writes; `API_WRITE_TOKEN`, if set, must be sent as a Bearer token.

**What this does not stop:** another device on the LAN that speaks HTTP can still call the write endpoints.
That is inherent to unauthenticated LAN access. Set `API_WRITES=off` or `API_WRITE_TOKEN` if that matters to
you. The stdio interface is not reachable from the network.

## Write actions

| Action | Limits |
|---|---|
| `wifi_kick_client` | MAC must be well-formed; the interface must be a known radio. The client can reconnect at once. |
| `reboot_modem` | Needs `confirm: "REBOOT"`; refused in the first 3 minutes after boot; one pending at a time; delay 5 to 300 s. |
| `dns_filter_pause` | At most one hour, held in RAM only. |
| `dns_filter_update` | Re-downloads the configured lists. |

Every attempt, allowed or refused, is written to `actions.log` beside the binary and to stderr.

## The DNS redirect

A runtime firewall rule, tagged with a comment, removed on stop, on failure and by reboot. It is removed
within about 1.5 seconds of the filter failing. See [dns-filter.md](dns-filter.md#failover).

## Known limits

- The device runs an old vendor kernel with closed-source modules. This project does not patch it.
- Telnet may be enabled by the firmware; prefer SSH, and disable remote access you do not use.
- Encrypted DNS (DoH/DoT) bypasses the filter.
- On some firmware versions the vendor shell lets an unprivileged CLI account become root without a
  password. This project uses root only to start itself at boot; treat the device's own accounts as part of
  your threat model.
