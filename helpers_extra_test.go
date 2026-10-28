package main

import (
	"net/netip"
	"strings"
	"testing"
)

func mustAddrPorts(t *testing.T, ss ...string) []netip.AddrPort {
	var out []netip.AddrPort
	for _, s := range ss {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, ap)
	}
	return out
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
