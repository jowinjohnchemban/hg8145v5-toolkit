# DNS filter

An optional, Pi-hole-style ad and tracker blocker built into the same binary (`filter.go`,
`dnsinspect.go`, `dnsnet.go`, `takeover.go`). It is off unless `FILTER_TAKEOVER=on` or `FILTER_PORT` is
set. Everything is configured through the service environment (`service.env`); nothing is hardcoded.

## How it works

```
LAN client -> port 53 --(local redirect)--> filter --> the modem's own resolver --> internet
```

- **Filter.** A DNS forwarder. A blocked name gets `0.0.0.0` / `::` (or NXDOMAIN with
  `FILTER_MODE=nxdomain`); everything else is forwarded untouched.
- **Upstream.** The modem's own resolver (found at runtime from the LAN bridge address), then the
  nameservers in `/etc/resolv.conf`. So it always follows whatever DNS the modem is configured with.
  The vendor resolver is never modified or replaced; it is simply the upstream.
- **Transparent mode** (`FILTER_TAKEOVER=on`). Every DNS query from the LAN on port 53, IPv4 and IPv6,
  is redirected to the filter, whatever resolver the device was told to use. No DHCP or GUI setting has
  to change, and nothing is keyed on an address, so changing the LAN address, DHCP DNS or WAN settings
  does not break it. The redirect is a runtime-only firewall rule tagged with a comment, so it can be
  found and removed without knowing any address, and a reboot clears it.
- **Not covered.** DNS-over-HTTPS and DNS-over-TLS cannot be seen. A device that uses them bypasses the
  filter.

## Lists

Block lists are downloaded outbound-only, parsed as a stream and kept **in RAM only** as sorted 64-bit
hashes (8 bytes per domain, about 600 KB for 76,000 domains). Nothing is written to flash. They are
re-downloaded at start and every `FILTER_REFRESH_HOURS` (default 24). If a download fails, nothing is
blocked (DNS keeps working) and the previous list is kept; at start the download retries every 10 seconds.

Supported syntax: hosts files, plain domain lists, and the whole-domain subset of uBlock/ABP syntax
(`||example.com^`, `||example.com^$all`, `@@||example.com^` for exceptions). Cosmetic filters, URL-path rules and scriptlets
need a browser and are ignored.

## Choosing lists

`FILTER_LISTS` takes any number of URLs, comma-separated; the lists are combined. Use the *Adblock* format
(`||domain^`) where a project offers it: it means "this domain and all its subdomains", which is how
wildcard lists such as [HaGeZi's](https://github.com/hagezi/dns-blocklists) are meant to be used. A hosts file
entry matches the exact name only.

Measured on the device (ARM, soft float):

| List | Domains | Load time after start | Peak memory |
|---|---|---|---|
| StevenBlack `hosts` | about 76,000 | a few seconds | a few MB |
| HaGeZi `adblock/multi.txt` | about 182,000 | about 6 s | about 13 MB |
| Both together | about 264,000 | a few more seconds | well under the 48 MB soft limit |

- **False positives:** with HaGeZi Multi loaded, none of 95 popular sites (Google, Microsoft, Apple, social,
  streaming, developer, CDN, Indian banking and government sites) were blocked. Other tiers were not tested;
  heavier tiers block more and are more likely to need entries in `FILTER_ALLOW_FILE`.
- **Combine them.** HaGeZi's lists leave out some large ad domains that StevenBlack blocks (for example
  `doubleclick.net` and `googleadservices.com`), and StevenBlack lacks much of what HaGeZi covers
  (telemetry and tracker families). Together they cover both.
- **Licences.** The lists are downloaded at runtime and not redistributed here. Check each project's

### uBlock Origin (Raymond Hill's uAssets) and malware lists

uBlock's own filter lists are about 98% browser-level rules (cosmetic filters, URL paths, scriptlets,
per-site and third-party options) that a DNS filter cannot apply. The parser therefore takes only what DNS can
express: plain `||domain^` rules and `||domain^$all` (every request type, the same as a domain block). Rules
with any other option are skipped, never widened, so a `||site^$3p` or `$doc` rule can never block a whole
site by accident.

Measured: the usable subset of uAssets `filters.txt`, `badware.txt`, `privacy.txt` and `resource-abuse.txt` is
about 1,270 domains, of which only about 180 are new on top of StevenBlack and HaGeZi. The malware-hosts
list from [malware-filter](https://gitlab.com/malware-filter/malware-filter) (built from abuse.ch URLhaus) adds about 2,300 live
malware hosts as exact names, about 2,100 of them new. Peter Lowe's list adds almost nothing (5 of 3,566 new)
and is not worth loading. None of these contained any of the 95 popular sites checked.
  licence before bundling any list.
## Avoiding false positives

- A hosts-file or bare-domain entry blocks **that exact name only**, as in Pi-hole. Only an explicit
  `||domain^` rule, or a regex, covers subdomains.
- An allow entry (`FILTER_ALLOW_FILE`, or `@@||domain^`) on a name or any parent always wins, including
  over CNAME inspection.
- **Deep CNAME inspection.** A harmless-looking name that is only an alias for a listed tracker domain is
  blocked too. It uses the lists only, never the regexes, and is skipped for names you allowed.
- **Never blocked:** reverse-lookup and local names (`.arpa`, `.local`, `.localhost`, `.invalid`, `.test`,
  `.lan`, `.home`) and the hosts the lists are downloaded from.
- `dns_filter_check {domain}` says whether a name would be blocked and why. `dns_filter_pause` turns blocking
  off for up to an hour while you investigate. Neither stores anything.

## Failover

A **separate watcher process** (`hg8145v5-mcp -dns-watch`, started by `service.sh`) owns the redirect.
Twice a second it sends a real query *through the filter to the upstream*, so it tests the whole path.

- Three failed probes in a row (about 1.5 s) remove the redirect, and DNS goes straight back to whatever
  resolver each client was using. If the filter process is simply dead the probe is refused instantly.
- Two good probes install it again, and a healthy watcher re-checks it every 10 s in case the firmware
  rebuilt its firewall chains.
- The watcher is independent of the filter and of its supervisor, so it still works if either dies
  in any way. `service.sh` runs a cleanup after every exit and respawns the watcher if it exits.
- A clean stop removes the redirect immediately.

Queries already in flight when the filter dies can stall for a few seconds on a stale connection-tracking
entry before the client retries; new queries are not affected.

## Settings

| Variable | Meaning |
|---|---|
| `FILTER_TAKEOVER` | `on` = transparent mode (recommended) |
| `FILTER_LISTS` | Comma-separated list URLs |
| `FILTER_REFRESH_HOURS` | List refresh interval, default 24 |
| `FILTER_DENY_FILE` / `FILTER_ALLOW_FILE` | Local deny / allow lists, one entry per line |
| `FILTER_REGEX_DENY_FILE` / `FILTER_REGEX_ALLOW_FILE` | Local regex lists (case-insensitive, `#` comments), matched on the full name; allow wins |
| `FILTER_MODE` | `null` (default) or `nxdomain` |
| `FILTER_PORT` | Local listen port, default 5335. It answers LAN clients only |
| `FILTER_UPSTREAM` | Fixed upstream instead of the modem's own resolver |
| `FILTER_IFACE` | LAN bridge name if it is not the first `br*` |

## Tools

| Tool | Kind | Purpose |
|---|---|---|
| `dns_filter` | read | State, domains loaded, last refresh, counters (never domain names) |
| `dns_filter_check` | read-only, POST | Would this domain be blocked, and why |
| `dns_filter_pause` | write | Pause blocking, 0 to 3600 seconds, 0 resumes |
| `dns_filter_update` | write | Re-download the lists now |

## Privacy

Only counters are kept. Queried and blocked domain names are never logged or stored, and the filter
only answers clients on the LAN, never the WAN side.
