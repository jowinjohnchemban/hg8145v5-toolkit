#!/bin/sh
# Minimal supervisor for hg8145v5-mcp on the modem (BusyBox ash).
# Usage: service.sh start|stop|status
# Respawns the binary if it exits. At boot it is started by the debug_start.sh hook
# (see docs/install.md, "Autostart").
DIR=$(cd "$(dirname "$0")" && pwd)
BIN="$DIR/hg8145v5-mcp-arm5"
# PID files can be overridden so a throwaway copy can be tested beside the live service.
PIDFILE=${HG_PIDFILE:-/tmp/hg8145v5-mcp.pid}
WDFILE=${HG_WDFILE:-/tmp/hg8145v5-mcp-wd.pid}

# Optional per-device settings (FILTER_*, API_*): a plain KEY=value file beside this script,
# kept on the device and never in git. Absent file = all optional features stay off.
if [ -f "$DIR/service.env" ]; then
	set -a
	. "$DIR/service.env"
	set +a
fi

# alive FILE: true only if FILE names a live process that really is one of ours. A bare
# `kill -0` is not enough: PIDs get reused, which once made `status` say "running" for a
# service that was long dead.
alive() {
	[ -f "$1" ] || return 1
	p=$(cat "$1")
	[ -n "$p" ] && [ -d "/proc/$p" ] && tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q "hg8145v5-mcp-arm5"
}

case "$1" in
start)
	if alive "$PIDFILE"; then echo "already running"; exit 0; fi
	rm -f "$PIDFILE"
	# The binary runs directly under this loop (no pipeline): a pipeline would make the shell wait
	# for its other half, so a crashed binary would never be noticed or restarted.
	# BusyBox here has no nohup/setsid, so the child ignores SIGHUP itself.
	# After every exit, however it happened, -dns-cleanup removes the optional DNS redirect.
	sh -c "trap '' HUP; while true; do HG_NO_STDIO=1 \"$BIN\"; \"$BIN\" -dns-cleanup; sleep 1; done" </dev/null >/dev/null 2>&1 &
	echo $! > "$PIDFILE"

	# Health watcher for the optional DNS redirect (FILTER_TAKEOVER=on; otherwise it exits
	# at once). It is a separate process on purpose: it probes the filter twice a second and
	# removes the redirect within about a second of the filter failing, even if the
	# supervisor above or the service died in any way, so DNS falls straight back to the
	# modem's own resolver. The loop restarts it if it ever exits.
	if [ "$FILTER_TAKEOVER" = on ] && ! alive "$WDFILE"; then
		sh -c "trap '' HUP; while true; do \"$BIN\" -dns-watch; sleep 2; done # hg8145v5-mcp-arm5 watcher" </dev/null >/dev/null 2>&1 &
		echo $! > "$WDFILE"
	fi
	echo started
	;;
stop)
	for f in "$PIDFILE" "$WDFILE"; do
		if alive "$f"; then kill "$(cat "$f")"; fi
		rm -f "$f"
	done
	for p in $(ps | grep "[h]g8145v5-mcp-arm5" | awk '{print $1}'); do kill "$p"; done
	"$BIN" -dns-cleanup # remove the optional DNS redirect, whatever state the process died in
	echo stopped
	;;
status)
	if alive "$PIDFILE"; then echo running; else echo stopped; fi
	;;
*)
	echo "usage: $0 start|stop|status"; exit 1
	;;
esac
