package main

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNomadServicesUnixSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "api.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var gotQ []string
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Nomad-Token") != "wi-token" || r.URL.Path != "/v1/service/web" {
			http.Error(w, "Permission denied", 403)
			return
		}
		gotQ = append(gotQ, r.URL.RawQuery)
		w.Header().Set("X-Nomad-Index", "42")
		w.Write([]byte(`[{"Address":"192.0.2.30","Port":8080,"NodeID":"n1"},{"Address":"2001:db8::5","Port":443},{"Address":"host.example","Port":1}]`))
	})}
	go srv.Serve(l)
	defer srv.Close()
	t.Setenv("NOMAD_SECRETS_DIR", filepath.Dir(sock))
	t.Setenv("NOMAD_TOKEN", "wi-token")
	t.Setenv("NOMAD_NAMESPACE", "staging")
	c, err := parse(t, "allow_nomad_services = web, other@ops\n")
	if err != nil {
		t.Fatal(err)
	}
	srcs, cc, err := buildSources(c)
	if err != nil || cc != nil || len(srcs) != 2 || srcs[0].key != "nomad:web" || srcs[1].key != "nomad:other@ops" {
		t.Fatalf("%v %v %v", srcs, cc, err)
	}
	ts, idx, err := srcs[0].fetch(context.Background(), 0, 0)
	if err != nil || idx != 42 || len(ts) != 2 || ts[0].String() != "192.0.2.30:8080" || ts[1].String() != "[2001:db8::5]:443" {
		t.Fatalf("%v %d %v", ts, idx, err)
	}
	if _, _, err := srcs[0].fetch(context.Background(), 42, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if gotQ[0] != "namespace=staging" || !strings.Contains(gotQ[1], "index=42") || !strings.Contains(gotQ[1], "wait=5s") {
		t.Fatalf("queries %v", gotQ)
	}
	if _, _, err := srcs[1].fetch(context.Background(), 0, 0); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want 403, got %v", err)
	}
}

func TestNomadConfig(t *testing.T) {
	for _, bad := range []string{"allow_nomad_services = a@\n", "allow_nomad_services = a b\n", "allow_nomad_services = @ns\n"} {
		if _, err := parse(t, bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	// Both sources merge: Consul + Nomad config parses with consul_addrs only required for Consul.
	if _, err := parse(t, "allow_nomad_services = web\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := parse(t, "allow_services = db\nallow_nomad_services = web\n"); err == nil {
		t.Fatal("consul services without consul_addrs accepted")
	}
}
