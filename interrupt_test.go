package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestConsulInterruptReloadsToken(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("X-Consul-Token"))
		n := len(seen)
		mu.Unlock()
		if n == 1 {
			<-r.Context().Done() // blocking query until interrupted
			return
		}
		w.Header().Set("X-Consul-Index", "5")
		w.Write([]byte("[]"))
	}))
	defer srv.Close()
	tf := filepath.Join(t.TempDir(), "tok")
	os.WriteFile(tf, []byte("old\n"), 0o600)
	cc := newConsulClient([]string{srv.URL}, tf, http.DefaultTransport.(*http.Transport).Clone())
	errc := make(chan error, 1)
	go func() {
		_, _, err := cc.Health(context.Background(), ServiceRef{Name: "x"}, 1, time.Minute, false)
		errc <- err
	}()
	time.Sleep(200 * time.Millisecond)
	os.WriteFile(tf, []byte("new\n"), 0o600)
	cc.Interrupt()
	select {
	case err := <-errc:
		if !errors.Is(err, errInterrupted) {
			t.Fatalf("err %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("not interrupted")
	}
	if _, idx, err := cc.Health(context.Background(), ServiceRef{Name: "x"}, 1, time.Minute, false); err != nil || idx != 5 {
		t.Fatalf("%v %d", err, idx)
	}
	if seen[0] != "old" || seen[1] != "new" {
		t.Fatalf("tokens %v", seen)
	}
	if cc.Failovers() != 0 {
		t.Fatal("interrupt counted as failure")
	}
}
