# Testing

There is no local Go toolchain requirement: CI (`go vet` plus a cross-compile) is the build check. The
behaviour below was verified on a real HG8145V5 running a Huawei firmware with a 3.10 kernel. Results from
one device are evidence, not a guarantee for other firmware versions.

## Verified on hardware

| Area | What was checked | Result |
|---|---|---|
| Tools | All read tools over HTTP and MCP stdio; write refusals (no confirm, bad MAC, unknown radio) | As designed |
| HTTP guards | 404, 405, 415, 403 (Origin, bad Host), 429 (rate limit) | As designed |
| Autostart | Real reboots with the chained hook | Service starts by itself; vendor boot unaffected |
| DNS blocking | Ad domains blocked, legitimate domains resolve, on the default resolver, the IPv6 resolver and a hard-coded public resolver | Correct |
| False positives | Exact entry vs subdomain, allow list, regex, CNAME into a listed domain, allow-listed alias, protected names | All correct |
| Filter crash (`kill -9` the filter) | Redirect removed in under a second; supervisor respawns; redirect returns | 700 lookups, none failed |
| Supervisor and filter killed together | Watcher alone removes the redirect | Gone within 4 s; DNS kept working |
| Clean stop / start | Redirect removed on stop, reinstalled on start | Correct |
| Full reboot | Everything comes back unassisted with the filter on | Blocking active when the LAN came back |

## Known limits of the evidence

- Lookups already in flight when the filter dies can stall for a few seconds (a stale connection-tracking
  entry); one such lookup took about 7 seconds. New lookups were unaffected.
- After a restart or reboot the lists are re-downloaded (about 20 seconds on this CPU), so blocking resumes
  a short while later. This fails open: DNS keeps working throughout.
- Not tested: other firmware versions, devices with a different LAN bridge name, IPv6-only clients,
  DNS-over-HTTPS clients, or the actual `reboot_modem` success path beyond a scheduled reboot.
