// actions.go holds the write actions: the only code in this binary that
// changes device state. Both the stdio MCP interface and the HTTP API reach
// these through the same callTool function, so their behaviour, guards and
// audit trail cannot drift apart.
//
// The set is deliberately small and each action is narrow, reversible, and
// built on a credential-free local tool:
//
//   - wifi_kick_client: deauthenticate one Wi-Fi client via hostapd_cli. The
//     client may reconnect straight away; nothing persistent changes.
//   - reboot_modem: restart the modem. It is the one action with real cost
//     (about 3 minutes with no internet, Wi-Fi or phone), so it needs an
//     explicit confirm token, a minimum uptime (a boot-loop guard), and only
//     one reboot can be pending at a time.
//
// Nothing here edits an OEM file, changes stored configuration, or touches
// flash. Every attempt, allowed or refused, is appended to actions.log next
// to the binary, best-effort.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

const (
	rebootConfirmToken = "REBOOT"
	rebootMinUptime    = 180.0 // seconds; refuse right after a boot so a bad state cannot loop
	rebootDefaultDelay = 10
	rebootMinDelay     = 5
	rebootMaxDelay     = 300
)

var rebootPending atomic.Bool

// auditAction records an action attempt to stderr and, best-effort, to
// actions.log beside the binary. A logging failure must never block or fail
// the action itself, so errors here are ignored.
func auditAction(format string, args ...any) {
	line := time.Now().UTC().Format(time.RFC3339) + " " + fmt.Sprintf(format, args...)
	log.Print(line)

	exe, err := os.Executable()
	if err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(filepath.Dir(exe), "actions.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(line + "\n")
}

func toolWifiKickClient(raw json.RawMessage) (string, error) {
	var a struct {
		Interface string `json:"interface"`
		MAC       string `json:"mac"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return "", fmt.Errorf("arguments must be a JSON object with interface and mac: %w", err)
	}
	if !macLine.MatchString(a.MAC) {
		auditAction("wifi_kick_client REFUSED invalid mac %q", a.MAC)
		return "", fmt.Errorf("mac %q is not a valid MAC address (expected aa:bb:cc:dd:ee:ff)", a.MAC)
	}

	// The interface must be one hostapd actually exposes; never pass an
	// arbitrary caller-supplied path or name through to the tool.
	var radio *hostapdRadio
	for _, r := range listRadios() {
		if r.Iface == a.Interface {
			rr := r
			radio = &rr
			break
		}
	}
	if radio == nil {
		auditAction("wifi_kick_client REFUSED unknown interface %q", a.Interface)
		return "", fmt.Errorf("interface %q is not a known Wi-Fi radio (see wifi_clients_count)", a.Interface)
	}

	out, err := hostapdCLI(*radio, "deauthenticate", a.MAC)
	result := strings.TrimSpace(string(out))
	auditAction("wifi_kick_client iface=%s mac=%s result=%q err=%v", a.Interface, a.MAC, result, err)
	if err != nil {
		return "", fmt.Errorf("hostapd_cli failed: %w (output: %s)", err, result)
	}
	return result, nil
}

func toolRebootModem(raw json.RawMessage) (string, error) {
	var a struct {
		Confirm      string `json:"confirm"`
		DelaySeconds int    `json:"delay_seconds"`
	}
	// A parse failure simply leaves Confirm empty, which is refused below.
	_ = json.Unmarshal(raw, &a)

	if a.Confirm != rebootConfirmToken {
		auditAction("reboot_modem REFUSED missing/incorrect confirm token")
		return "", fmt.Errorf("refusing: this reboots the household's only internet, Wi-Fi and phone gateway (about 3 minutes offline). Call again with confirm set to exactly %q to proceed", rebootConfirmToken)
	}
	if up := collectSystemInfo().UptimeSeconds; up < rebootMinUptime {
		auditAction("reboot_modem REFUSED uptime %.0fs below %.0fs", up, rebootMinUptime)
		return "", fmt.Errorf("refusing: the modem booted only %.0f seconds ago (minimum %.0f), which guards against a reboot loop", up, rebootMinUptime)
	}

	delay := a.DelaySeconds
	if delay == 0 {
		delay = rebootDefaultDelay
	}
	if delay < rebootMinDelay {
		delay = rebootMinDelay
	}
	if delay > rebootMaxDelay {
		delay = rebootMaxDelay
	}

	if !rebootPending.CompareAndSwap(false, true) {
		auditAction("reboot_modem REFUSED already pending")
		return "", fmt.Errorf("a reboot is already scheduled")
	}
	auditAction("reboot_modem scheduled in %ds", delay)

	go func() {
		time.Sleep(time.Duration(delay) * time.Second)
		auditAction("reboot_modem executing")
		if out, err := exec.Command("reboot").CombinedOutput(); err != nil {
			// Not running with enough privilege, or reboot is unavailable:
			// clear the pending flag so a later attempt isn't blocked.
			auditAction("reboot_modem FAILED: %v (%s)", err, strings.TrimSpace(string(out)))
			rebootPending.Store(false)
		}
	}()
	return fmt.Sprintf("reboot scheduled in %d seconds; the modem will be offline for about 3 minutes", delay), nil
}
