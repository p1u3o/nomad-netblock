# nomad-netpush

`netblock netpush` is a small unprivileged forwarder that runs as a sidecar task. Each
declared upstream gets a local loopback listener (TCP or UDP); connections to it are
forwarded to a healthy instance of a Consul or Nomad native service. An optional DNS
resolver answers upstream names with their loopback IP, so the app can just connect to
`mysql:3306`.

It ships in the netblock image (same Go module and binary). It needs no capabilities
and no root.

Status: phase 1 (TCP and UDP forwarding, Consul and Nomad discovery, drain,
standalone DNS, Prometheus metrics) staging-tested. On-demand mode, port-53
redirect, egress lockdown and `max_conns` are built in 0.4.0-rc3 (see below) but
not yet staging-tested.

## How it works

* **Discovery.** One blocking query per upstream:
  * `consul:` uses `/v1/health/service/<name>`. By default it keeps passing
    instances only (`only_passing=true`). With `only_passing=false` it keeps every
    instance that is not critical. The token is the task's Consul workload identity
    token (`consul_token_file`, default `/secrets/consul_token`). `consul_addrs` fail
    over the same way as netblock.
  * `nomad:` uses the Nomad native service API through the Task API socket with the
    task's default workload identity (`identity { env = true }` or `file = true`).
  * On errors it backs off (1 s to 30 s) and keeps the last good target list.
* **Balancing.** `least_conn` (default; ties go round robin), `round_robin` or
  `first`. On a failed connect it retries another target, up to `connect_retries`
  (default 2, so three tries). If no target is left, the client connection is closed.
* **Target changes and drain.** New connections only go to current targets.
  Existing connections to a removed target keep working and are marked draining.
  * They are closed after `drain_timeout` (default `5m`). With `drain_timeout = 0`
    they are never force-closed.
  * If the target comes back first, the drain is cancelled.
  * TCP keepalive (`tcp_keepalive`, default 30 s) is set on both sides, so dead peers
    behind NAT or conntrack are noticed.
* **UDP.** Each client address gets one session: a connected socket to the chosen
  target, with replies sent back from the listener. A session ends after `udp_idle`
  (default 60 s) without traffic, or when it is drained.
* **DNS** (`dns_listen`):
  * Upstream names, and `name.<suffix>` for each `dns_suffixes` entry, are answered
    with TTL 5 s: `A` gives the bind IP, and `SRV` gives the bind port plus an
    additional `A`. Other types (including `AAAA`) get an empty NOERROR.
  * Other names are passed unchanged to `dns_upstream` (`dns_default = passthrough`,
    the standalone mode). With `dns_default = nxdomain` they are answered NXDOMAIN
    and logged.
  * Both UDP and TCP are served.
* **Metrics** on `metrics_addr` (default `127.0.0.1:9811`). `/metrics` serves
  Prometheus text, and `/ready` returns 200 once every upstream has had one
  successful discovery.

## Config (`/local/netpush.conf`)

```
consul_addrs     = 10.0.0.10:8501, 10.0.0.11:8501   # needed for consul: sources
consul_tls_server_name = server.dc1.consul           # optional
consul_ca_file   = /local/consul-ca.pem
consul_token_file = /secrets/consul_token
nomad_addr       =                                   # default: Task API socket

# upstream = <name> source=consul:<svc>[@dc]|consul:<tag>.<svc>[@dc]|nomad:<svc>[@ns]
#            port=<local port> [bind=127.0.1.x] [protocol=tcp|udp]
#            [balance=least_conn|round_robin|first] [only_passing=true|false] [udp_idle=60s]
#            [max_conns=N]
upstream = mysql  source=consul:mysql-prod port=3306
upstream = redis  source=nomad:redis port=6379 balance=first
upstream = statsd source=consul:statsd port=8125 protocol=udp

bind_pool        = 127.0.1.0/24   # auto bind IPs, assigned in upstream order from .1
drain_timeout    = 5m             # 0 = never force-close
connect_timeout  = 3s
connect_retries  = 2
tcp_keepalive    = 30s            # 0 = off
metrics_addr     = 127.0.0.1:9811

dns_listen   = 127.0.0.1:53      # empty = no resolver
dns_upstream = auto              # auto (resolv.conf, loopback skipped) | none | IP list
dns_default  = passthrough       # or nxdomain
dns_suffixes = service.consul
```

Notes:

* Upstream names must be valid DNS labels and unique. An auto-assigned IP is
  stable as long as the upstream order does not change. Pin `bind=` if other
  config depends on it.
* The listener port is the `port=`; the target port comes from discovery.
* Binding ports below 1024 (DNS on 53) as non-root needs
  `net.ipv4.ip_unprivileged_port_start` in the group's network namespace. Docker
  sets it to 0 for bridge-mode containers, so check this for `bridge` networking.
  Otherwise use a high `dns_listen` port and point the app at it.

## Example job snippet

```hcl
group "app" {
  network {
    mode = "bridge"
    dns {
      # netpush first; the real resolver as a fallback if netpush is down
      servers = ["127.0.0.1", "10.0.0.2"]
    }
  }

  task "netpush" {
    driver = "docker"
    user   = "65534:65534"
    lifecycle {
      hook    = "prestart"
      sidecar = true
    }
    consul {}                   # Consul workload identity -> /secrets/consul_token
    identity {                  # Nomad workload identity for nomad: sources
      file = true
    }
    config {
      image = "ghcr.io/p1u3o/nomad-netblock:0.4.0"
      args  = ["netpush", "/local/netpush.conf"]
    }
    template {
      destination = "local/netpush.conf"
      data        = <<-EOT
        consul_addrs = {{ range service "consul" }}{{ .Address }}:8501,{{ end }}
        upstream = mysql source=consul:mysql-prod port=3306
        dns_listen = 127.0.0.1:53
        dns_upstream = 10.0.0.2
      EOT
    }
    template {
      destination = "local/consul-ca.pem"
      data        = "{{ key \"pki/consul-ca\" }}"
    }
    resources {
      cpu    = 50
      memory = 32
    }
  }

  task "app" {
    # connects to mysql:3306 -> 127.0.1.1:3306 -> a passing mysql-prod instance
  }
}
```

The `consul_addrs` template line and the CA key path are placeholders; use the same
values as the group's netblock config. If the app starts before netpush has bound its
listeners, the first connections are refused. Prestart sidecars are started before the
main task, but Nomad does not wait for `/ready`.

## On-demand mode (0.4.0-rc3, not yet staging-tested)

Off by default. With `ondemand = true` the app does not need to declare its
upstreams: the first DNS lookup of a service name (bare label or
`<name>.<dns_suffix>`) that matches `ondemand_allow` gets a stable loopback IP
from `ondemand_pool`, and any port on that IP is forwarded to the service's
current instances on their dynamic ports. Needs netblock (`netpush_socket` in
netblock's config, `netblock_exempt_socket` here) and `dns_listen`.

```
ondemand           = true
ondemand_source    = consul          # consul | nomad | nomad@<namespace>
ondemand_allow     = mx-*, smtp-*    # glob patterns; empty = any name
ondemand_pool      = 127.0.3.0/24    # must not overlap bind_pool (127.0.2.x is used by kvlock's peer-expose)
ondemand_max       = 64              # services; also capped by the pool size
ondemand_port      = 15001           # single capture listener (TCP and UDP)
ondemand_udp_idle  = 60s
ondemand_max_conns = 0               # per on-demand service, 0 = unlimited
```

DNS answers for on-demand names:

| case | answer |
|---|---|
| declared `upstream` with the same name | the upstream's bind IP (declared wins) |
| name matches, service has instances | A, TTL 5, IP from the pool (AAAA: NODATA) |
| name does not match `ondemand_allow` | NXDOMAIN (`refused{reason="pattern"}`) |
| no instances on the first lookup | NXDOMAIN (`reason="unknown"`); it is retried on the next lookup |
| pool or `ondemand_max` full | SERVFAIL (`reason="pool_full"`) |
| discovery or netblock allow failed | SERVFAIL (`reason="error"`) |

Once assigned, a name keeps its IP for the life of the task; instance changes are
followed by a blocking watch with the usual drain.

How the traffic gets to netpush (rules are in netblock's `ip netblock` table, so
netblock must have `ondemand_pool` set to the same pool):

* TCP: `nat output` `ip daddr <pool> redirect to :15001`. netpush reads the
  original destination with `SO_ORIGINAL_DST`. REDIRECT (not TPROXY) because
  the traffic is locally generated: TPROXY only works in prerouting, and
  REDIRECT + `SO_ORIGINAL_DST` needs no special socket options in netpush.
* UDP: there is no `SO_ORIGINAL_DST` for UDP, so this uses TPROXY in
  prerouting on `lo` (`iif "lo" ip daddr <pool> meta l4proto udp tproxy ip to
  127.0.0.1:15001`). The listener needs `IP_TRANSPARENT` (CAP_NET_ADMIN), which
  netpush does not have, so netblock watch creates the socket and passes it over
  the registration socket; netpush reads `IP_ORIGDSTADDR` per datagram and
  answers from a per-session socket bound to the original pool IP.
* The resolved service is added to netblock's allow sets: netpush asks watch
  (`allow consul <name>` / `allow nomad <name>`) before it answers the DNS query,
  and watch replies once the instances are in `svc4`/`svc6`. Watch checks the
  name against its own `ondemand_allow` and `ondemand_max`, so a compromised
  netpush cannot open arbitrary services. The list is replayed if watch restarts.

netblock config keys (new in 0.4.0-rc3):

```
ondemand_pool   = 127.0.3.0/24   # enables the capture rules; needs netpush_socket
ondemand_port   = 15001
ondemand_allow  = mx-*           # checked again on watch's side
ondemand_max    = 64
dns_redirect    = 53             # redirect port-53 traffic of every uid except netpush_uid
                                 # (to 127/8 excluded) to netpush's dns_listen port
egress_lockdown = netpush        # resolver, service-set and allow_cidrs accept rules only
                                 # for netpush_uid; the app can only reach the network via netpush
```

Notes:

* The Consul token of the group needs `service:read` (and `node:read`) on the
  names `ondemand_allow` can match, for both netpush and watch.
* Search domains in the app's resolv.conf are tried first (`mx-a.default.svc...`).
  Those do not match a `dns_suffixes` entry, so they pass through; only the
  bare name or `<name>.<suffix>` is on-demand.
* Ports below 1024 on the pool IP work with any app because the listener is
  15001; only `dns_listen` on 53 needs `ip_unprivileged_port_start`.
* `max_conns=N` on a declared `upstream` (or `ondemand_max_conns`) refuses new
  TCP connections/UDP sessions above N (`netpush_conn_limit_rejects_total`).

New metrics: `netpush_ondemand_pool_size`, `netpush_ondemand_pool_used`,
`netpush_ondemand_refused_total{reason}` (`pattern`, `unknown`, `pool_full`,
`error`, `unassigned` = connection to a pool IP nobody was given),
`netpush_conn_limit_rejects_total`, DNS kinds `ondemand` and `ondemand_nodata`;
netblock: `netblock_ondemand_services` and nft counters `ondemand_tcp`,
`ondemand_udp`, `dns_redirect`. On-demand upstreams use `protocol="ondemand"`.

## Metrics

All metrics are labelled `upstream` and `protocol`.

| metric | meaning |
|---|---|
| `netpush_connections_active` | open connections / UDP sessions |
| `netpush_connections_total` | forwarded connections / sessions |
| `netpush_connections_draining` | connections whose target was removed |
| `netpush_drain_forced_closes_total` | closed by `drain_timeout` |
| `netpush_connect_failures_total`, `netpush_connect_retries_total` | dial failures, retries on another target |
| `netpush_no_target_total` | clients refused because no target was available |
| `netpush_bytes_up_total`, `netpush_bytes_down_total` | client→target, target→client |
| `netpush_targets` | healthy targets from discovery |
| `netpush_discovery_errors_total` | failed discovery queries |
| `netpush_last_target{target}` | target of the latest connection |
| `netpush_dns_answers_total{kind}` | `upstream`, `upstream_nodata`, `passthrough`, `nxdomain`, `servfail`, `refused` |

## Not built yet / open

* Staging test of on-demand mode, `dns_redirect` and `egress_lockdown` (rc3).
* DoH/DoT: `dns_redirect` only catches port 53; blocking known DoH endpoints is not built
  (with `egress_lockdown` the app cannot reach them anyway).
* CI policy check of job configs (patterns, pool overlap) is not built.
* TLS origination and rate limits (per-upstream `max_conns` is built).
* IPv6 on-demand pool (IPv4 loopback only).
* Turning on Consul workload identity cluster-wide (auth method, binding rules).
