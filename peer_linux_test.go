//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestPeerHandshake(t *testing.T) {
	var fs syscall.Statfs_t
	if err := syscall.Statfs(cgroupRoot, &fs); err != nil || fs.Type != cgroup2Magic {
		t.Skip("no cgroup2 at", cgroupRoot)
	}
	id, _ := cgroupID(cgroupRoot)
	defer func(o uint64) { rootCgroupID = o }(rootCgroupID)
	rootCgroupID = 0 // test boxes often run in the root cgroup
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := defaultConfig()
	c.NetpushSocket = filepath.Join(t.TempDir(), "s")
	c.NetpushUID = os.Getuid()
	out := make(chan peerReg, 1)
	go servePeer(ctx, c, 0, out, nil)
	go registerWithNetblock(ctx, c.NetpushSocket)
	select {
	case r := <-out:
		if r.id != id || r.uid != os.Getuid() {
			t.Fatalf("got id %d uid %d, want %d %d", r.id, r.uid, id, os.Getuid())
		}
		r.f.Close()
	case <-ctx.Done():
		t.Fatal("no registration")
	}
	// Own cgroup is rejected.
	c2 := c
	c2.NetpushSocket = filepath.Join(t.TempDir(), "s2")
	out2 := make(chan peerReg, 1)
	go servePeer(ctx, c2, id, out2, nil)
	waitSock(t, c2.NetpushSocket)
	if err := registerOnce(ctx, c2.NetpushSocket); err == nil || err == errPeerClosed || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("own cgroup accepted: %v", err)
	}
	// Wrong uid is rejected.
	c3 := c
	c3.NetpushSocket = filepath.Join(t.TempDir(), "s3")
	c3.NetpushUID = os.Getuid() + 1
	go servePeer(ctx, c3, 0, make(chan peerReg), nil)
	waitSock(t, c3.NetpushSocket)
	if err := registerOnce(ctx, c3.NetpushSocket); err == nil || err == errPeerClosed || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("wrong uid accepted: %v", err)
	}
}

func waitSock(t *testing.T, p string) {
	for i := 0; i < 200; i++ {
		if _, err := os.Stat(p); err == nil {
			time.Sleep(20 * time.Millisecond) // chmod after listen
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("socket never appeared")
}
