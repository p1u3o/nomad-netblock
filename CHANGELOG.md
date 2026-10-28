# Changelog

## 0.4.0-rc5 (prerelease)
- 0.4.0-rc4: with `dns_redirect` and `egress_lockdown`, queries redirected from a remote resolver were
  dropped (the filter output hook still sees the original interface, so `oif "lo" accept` misses them). The output
  chain now accepts dnat'ed packets to 127.0.0.1 on the `dns_redirect` port.
- On-demand mode (0.4.0-rc3): `ondemand = true` in netpush and `ondemand_pool` in netblock. The first DNS lookup of
  a service matching `ondemand_allow` gets a stable IP from 127.0.3.0/24; any TCP or UDP port on it is forwarded to
  the current instances (TCP via nat REDIRECT and SO_ORIGINAL_DST, UDP via TPROXY with the listener socket created by
  watch). Names not matching the pattern get NXDOMAIN, a full pool gets SERVFAIL. Resolved services are added to
  netblock's allow sets through the registration socket, checked against watch's own pattern and limit.
- netblock: `dns_redirect = <port>` sends port-53 traffic from every uid except netpush to netpush's resolver;
  `egress_lockdown = netpush` limits the service, resolver and allow_cidrs accept rules to netpush's uid.
- netpush: `max_conns=N` per upstream and `ondemand_max_conns`; new on-demand and limit metrics.
- netpush: DNS listener on port 0 now retries if the TCP port is taken (fixes an intermittent test failure).
- Fix a panic in netpush's registration reader when the connection closes with an error.
- netpush: when watch's registration socket is unreachable, log the error once and then at most once a minute
  (with the number of attempts not logged) instead of every 2s.
- New `netblock netpush [conf]` mode (nomad-netpush phase 1): an unprivileged sidecar that binds loopback listeners
  per declared upstream and forwards TCP and UDP to Consul (passing-only by default) or Nomad native service
  instances, with least_conn/round_robin/first balancing, connect retries, TCP keepalives and drain on target change
  (`drain_timeout`, default 5m, 0 = never). Optional DNS resolver for upstream names with passthrough, Prometheus
  metrics on 127.0.0.1:9811. See docs/nomad-netpush.md.

## 0.3.2 (2026-10-25)
- Fix: with `run_as`, any process in the alloc running as the same uid (e.g. 65532) could reach Consul through the
  `meta skuid` accept rule. watch now resolves its own cgroup from /proc/self/cgroup at start and matches Consul traffic
  with `socket cgroupv2 level N "<path>"` (with `meta skuid` kept as an extra condition when `run_as` is set).
- If the cgroup cannot be used (missing or not yet created, deleted, unusual path, cgroup v1) or the rule does not match
  in practice (probe to the Consul endpoints leaves the new `consul_exempt` counter at 0), watch logs
  `CGROUP EXEMPT FALLBACK: ...` and uses the old uid match.
- init no longer adds a Consul exemption when `run_as` is set (init fetches before the rules are applied); without
  `run_as` it keeps the open Consul rule as before.
- New key `exempt_match = auto|uid` (default `auto`).
- Tests for cgroup parsing, rule rendering, fallback and the counter check.

## 0.3.1
- Several Consul endpoints (`consul_addrs`) with failover; `run_as` non-root watch.
