#!/bin/sh
# Resident hg8145v5-mcp autostart hook, installed at /mnt/jffs2/debug_start.sh.
#
# This is Huawei's own supported debug entry point: 1.sdk_init.sh runs this
# file (if present) very early in boot -- before any driver or service is
# started -- then unconditionally renames it to debug_startbak.sh and calls
# `exit`, which otherwise skips the rest of boot entirely. See
# docs/install.md ("Autostart") for why that is unsafe to leave as-is.
#
# How this hook survives every reboot without ever blocking real boot:
#   1. Confirm the real boot script is actually there and runnable. If not,
#      change nothing and get out of the way -- better to fall back to
#      Huawei's original (bad but known) behavior than to guess.
#   2. Move the real debug_start.sh out of the way under a different name,
#      so the second (chained) invocation of 1.sdk_init.sh below does not
#      see it -- so it neither calls us again (which would loop) nor hits
#      the original script's own "mv; exit" (which would abort boot again).
#   3. Start our service in the background. A failure here is logged but
#      never allowed to stop real boot from proceeding.
#   4. In a detached background subshell, wait until the chained boot has
#      certainly passed its own debug_start.sh check (a generous margin),
#      then restore debug_start.sh so the NEXT reboot repeats this cycle.
#      This runs in a forked child, which `exec` below does not affect.
#      If the restore itself fails, that's logged too, but by then real
#      boot is already running independently of this script.
#   5. `exec` a fresh copy of the real boot script. `exec` replaces this
#      process, so the ORIGINAL invocation's own "mv; exit" lines (which
#      called us) never execute -- the fresh invocation instead finds no
#      debug_start.sh and proceeds straight into real boot (drivers, WAN,
#      Wi-Fi, voice) for the first and only time this boot.
#
# Every step from here on is defensive on purpose: nothing in this file is
# allowed to be the reason real boot (step 5 onward, which is Huawei's own
# unmodified script) fails to run. If this script's own logic breaks, the
# worst case is our MCP service does not start or does not re-arm for next
# reboot -- never a WAN/Wi-Fi/voice outage caused by this hook itself.

REAL=/mnt/jffs2/debug_start.sh
STASH=/mnt/jffs2/.debug_start.sh.boot-stash
SDKINIT=/etc/rc.d/rc.start/1.sdk_init.sh
SERVICE=/mnt/jffs2/hg8145v5-mcp/service.sh
LOG=/mnt/jffs2/hg8145v5-mcp/boot-hook.log

log() {
	# best-effort only: if /mnt/jffs2 is somehow unwritable, don't let
	# logging itself be a new way for this script to misbehave.
	echo "$(date 2>/dev/null) $*" >>"$LOG" 2>/dev/null
}

# Hard recursion guard. This is the one thing that must never be allowed to
# loop: if the mv below somehow fails (jffs2 error, race, anything), the
# chained 1.sdk_init.sh would find debug_start.sh present again and call us
# a second time. HG8145V5_HOOK_DEPTH, once exported, is inherited by that
# second call via the environment regardless of whether the mv succeeded.
# Tripping this guard means we exit immediately with no further exec, so
# the chained invocation falls through to Huawei's own original "mv;
# exit" -- boot aborts exactly once, the same (bad but bounded) failure
# mode as if this hook didn't exist, and never an unbounded loop.
if [ -n "$HG8145V5_HOOK_DEPTH" ]; then
	log "ABORT: re-entered hook (depth guard tripped, stash likely failed) -- not retrying"
	exit 0
fi

if [ ! -x "$SDKINIT" ]; then
	log "ABORT: $SDKINIT missing or not executable -- leaving debug_start.sh in place, not starting our service, falling back to original boot behavior"
	exit 0
fi

mv -f "$REAL" "$STASH" 2>>"$LOG" || log "WARN: could not stash $REAL -- depth guard will stop this from looping"

if [ -x "$SERVICE" ]; then
	"$SERVICE" start >>"$LOG" 2>&1 || log "WARN: $SERVICE start exited non-zero"
else
	log "WARN: $SERVICE missing or not executable -- skipping service start"
fi

( sleep 30
  # mv, not cp: restores REAL and removes STASH in one step, so no stale
  # stash file is left lying around on /mnt/jffs2 after a normal boot.
  if [ -f "$STASH" ]; then
    mv -f "$STASH" "$REAL" 2>>"$LOG" || log "WARN: could not restore $REAL from $STASH"
  fi
) &

export HG8145V5_HOOK_DEPTH=1
exec "$SDKINIT"
