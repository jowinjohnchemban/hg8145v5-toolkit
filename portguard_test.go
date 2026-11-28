package main

import (
	"reflect"
	"testing"
)

func TestGuardChainRulesReturnLANThenDropEverythingElse(t *testing.T) {
	got := guardChainRules([]string{"lo", "br+"})
	want := []string{
		"-A HG_GUARD -i lo -j RETURN",
		"-A HG_GUARD -i br+ -j RETURN",
		"-A HG_GUARD -j DROP",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("chain rules = %v, want %v", got, want)
	}
	// The DROP must come last, so an update that appends rules in order never blocks the LAN midway.
	if got[len(got)-1] != "-A HG_GUARD -j DROP" {
		t.Fatalf("DROP is not last: %v", got)
	}
}

func TestGuardJumpArgs(t *testing.T) {
	ins := guardJumpArgs("-I", guardPort{"udp", "5335"})
	wantIns := []string{"-I", "INPUT", "1", "-p", "udp", "--dport", "5335",
		"-m", "comment", "--comment", "hg8145v5-guard", "-j", "HG_GUARD"}
	if !reflect.DeepEqual(ins, wantIns) {
		t.Fatalf("insert args = %v, want %v", ins, wantIns)
	}
	del := guardJumpArgs("-D", guardPort{"tcp", "8099"})
	if del[0] != "-D" || del[2] == "1" {
		t.Fatalf("delete args must not carry a rule position: %v", del)
	}
}

func TestGuardedPortsFollowTheSettings(t *testing.T) {
	t.Setenv("FILTER_TAKEOVER", "")
	t.Setenv("FILTER_PORT", "")
	t.Setenv("API_ADDR", "")
	t.Setenv("API_PORT", "")
	ports := guardedPorts() // filter off: only the API and mDNS
	want := []guardPort{{"tcp", "8099"}, {"udp", "5353"}}
	if !reflect.DeepEqual(ports, want) {
		t.Fatalf("ports = %v, want %v", ports, want)
	}

	t.Setenv("FILTER_TAKEOVER", "on")
	t.Setenv("API_ADDR", "192.0.2.1:9000") // an explicit address decides the API port
	ports = guardedPorts()
	want = []guardPort{{"udp", "5335"}, {"tcp", "5335"}, {"tcp", "9000"}, {"udp", "5353"}}
	if !reflect.DeepEqual(ports, want) {
		t.Fatalf("ports = %v, want %v", ports, want)
	}
}

func TestGuardNeverTouchesVendorOrPrivilegedPorts(t *testing.T) {
	for _, port := range []string{"53", "67", "80", "443", "1900", "5060", "7547", "37443", "0", "70000", "abc", ""} {
		if guardable(port) {
			t.Errorf("port %q must not be guardable", port)
		}
	}
	for _, port := range []string{"5335", "8099", "5353", "9000"} {
		if !guardable(port) {
			t.Errorf("port %q should be guardable", port)
		}
	}
	// A mistyped setting must drop out of the list rather than reach the firewall.
	t.Setenv("FILTER_TAKEOVER", "on")
	t.Setenv("FILTER_PORT", "5060") // the voice port
	t.Setenv("API_ADDR", "")
	t.Setenv("API_PORT", "")
	for _, gp := range guardedPorts() {
		if gp.port == "5060" {
			t.Fatalf("the SIP port was selected for guarding: %v", gp)
		}
	}
}

func TestGuardCanBeSwitchedOff(t *testing.T) {
	t.Setenv("PORT_GUARD", "")
	if !guardEnabled() {
		t.Fatal("the guard must be on by default")
	}
	t.Setenv("PORT_GUARD", "OFF")
	if guardEnabled() {
		t.Fatal("PORT_GUARD=off must disable it")
	}
}

func TestSameLines(t *testing.T) {
	if !sameLines([]string{"a", "b"}, []string{"a", "b"}) || sameLines([]string{"a"}, []string{"a", "b"}) ||
		sameLines([]string{"a", "b"}, []string{"b", "a"}) {
		t.Fatal("sameLines must compare length and order")
	}
}
