# Install

This is a manual install onto a device you own. Read [security.md](security.md) first, and keep a backup of
the device's flash before writing anything to it. The device is your live internet, Wi-Fi and phone
gateway: treat any write to `/mnt/jffs2` as something that could cause an outage.

## 1. Get the binary

Every push builds it in CI (`.github/workflows/build.yml`); download the `hg8145v5-mcp-arm5` artifact, or
build it yourself:

```sh
GOOS=linux GOARCH=arm GOARM=5 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o hg8145v5-mcp-arm5 .
```

`GOARM=5` is required (the kernel has no VFP). Check the size against free space first
(`df -h /mnt/jffs2` on the device) and leave room to spare.

## 2. Copy the files

You need a root shell on the device. Copy these into one directory under `/mnt/jffs2`, for example
`/mnt/jffs2/hg8145v5-mcp/`, by any method you have (SCP, or a one-shot `nc` transfer), then `chmod 755` them:

| File | Purpose |
|---|---|
| `hg8145v5-mcp-arm5` | the binary |
| `service.sh` | supervisor: start, stop, status |
| `service.env` | your settings, copied from `service.env.example`. Stays on the device. |

Verify the checksum of the binary on the device against the one you built.

## 3. Start it by hand first

```sh
sh /mnt/jffs2/hg8145v5-mcp/service.sh start
sh /mnt/jffs2/hg8145v5-mcp/service.sh status
```

Then, from another machine on the LAN: `curl http://<modem>:8099/api/tools/service_info`. Do not wire up
autostart until this works.

## 4. Autostart (optional)

Install `debug_start.sh` as `/mnt/jffs2/debug_start.sh` (mode 755). It is a chained version of the
firmware's own debug hook; how it works and why it is safe is in [architecture.md](architecture.md). On the
next boot it starts `service.sh`, hands control straight back to the vendor's boot script, and restores
itself. If anything is unexpected it steps aside and the device boots normally.

## 5. The DNS filter (optional)

Edit `service.env` (see [dns-filter.md](dns-filter.md)), then restart the service. Test it from one device
before relying on it:

```sh
service.sh stop && service.sh start
curl http://<modem>:8099/api/tools/dns_filter
```

## Uninstall and rollback

```sh
sh /mnt/jffs2/hg8145v5-mcp/service.sh stop      # also removes the DNS redirect
rm -f /mnt/jffs2/debug_start.sh /mnt/jffs2/debug_startbak.sh   # only if you installed the hook
rm -rf /mnt/jffs2/hg8145v5-mcp
```

The runtime firewall rules and listeners disappear on a reboot. Nothing outside `/mnt/jffs2` was changed.
