//go:build !linux

package main

import (
	"context"
	"net"
)

func (o *onDemand) serveTCP(ctx context.Context, ln *net.TCPListener) {
	logf("ondemand: not supported on this OS")
}
func (o *onDemand) getUDPListener(context.Context, *netblockLink) *net.UDPConn { return nil }
func (o *onDemand) serveUDP(context.Context, *net.UDPConn)                     {}
