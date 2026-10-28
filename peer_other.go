//go:build !linux

package main

import (
	"context"
	"errors"
	"os"
)

type peerReg struct {
	f   *os.File
	id  uint64
	uid int
}

func currentPeerFile() *os.File                    { return nil }
func setPeerFile(f *os.File) *os.File              { return nil }
func cgroupID(string) (uint64, error)              { return 0, nil }
func registerWithNetblock(context.Context, string) {}

type odRequest struct {
	kind, name string
	reply      chan error
}

func registerWithNetblockLink(context.Context, string, *netblockLink) {}

type netblockLink struct{ onRegister func() }

func newNetblockLink() *netblockLink { return &netblockLink{} }
func (l *netblockLink) request(context.Context, string) (string, *os.File, error) {
	return "", nil, errors.New("not supported on this OS")
}
func servePeer(_ context.Context, c Config, _ uint64, _ chan<- peerReg, _ chan<- odRequest) {
	logf("watch: NETPUSH EXEMPT DISABLED: not supported on this OS")
}
