# Example: bridge-mode job with nomad-netblock egress default deny.
# Config: nomad var put nomad/jobs/example mode=enforce allow_services=postgres consul_addrs=192.0.2.10:8501 run_as=65532
job "example" {
  datacenters = ["dc1"]
  type        = "service"

  group "app" {
    network {
      mode = "bridge"
      port "http" { to = 8080 }
    }

    task "netblock-init" {
      driver = "docker"
      identity { env = true }   # only needed for allow_nomad_services
      lifecycle {
        hook    = "prestart"
        sidecar = false
      }
      config {
        image   = "ghcr.io/p1u3o/nomad-netblock:0.3.1"
        args    = ["init"]
        cap_add = ["net_admin"]
      }
      artifact {
        source      = "https://vault.example.com/v1/pki_int/ca_chain"   # CA for the Consul HTTPS API
        destination = "local/consul-ca.pem"
        mode        = "file"
      }
      template {
        destination = "local/netblock.conf"
        data        = file("netblock.conf.tpl")
        change_mode = "noop"
      }
      template {
        destination = "secrets/consul.token"
        perms       = "0400"
        data        = "{{ with nomadVar \"nomad/jobs/example/app/netblock-init\" }}{{ .consul_token }}{{ end }}"
        change_mode = "noop"
      }
      resources {
        cpu    = 50
        memory = 48
      }
    }

    task "netblock-watch" {
      driver = "docker"
      identity { env = true }
      lifecycle {
        hook    = "poststart"
        sidecar = true
      }
      config {
        image   = "ghcr.io/p1u3o/nomad-netblock:0.3.1"
        args    = ["watch"]
        cap_add = ["net_admin"]
      }
      artifact {
        source      = "https://vault.example.com/v1/pki_int/ca_chain"
        destination = "local/consul-ca.pem"
        mode        = "file"
      }
      template {
        destination = "local/netblock.conf"
        data        = file("netblock.conf.tpl")
        change_mode = "restart"
      }
      template {
        destination = "secrets/consul.token"
        perms       = "0400"
        uid         = 65532   # matches run_as
        gid         = 65532
        data        = "{{ with nomadVar \"nomad/jobs/example/app/netblock-watch\" }}{{ .consul_token }}{{ end }}"
        change_mode = "restart"
      }
      resources {
        cpu    = 50
        memory = 48
      }
    }

    task "app" {
      driver = "docker"
      leader = true
      config {
        image    = "example/app:1.0"
        ports    = ["http"]
        cap_drop = ["setuid", "setgid"]   # keeps the run_as skuid rule meaningful
      }
    }
  }
}
