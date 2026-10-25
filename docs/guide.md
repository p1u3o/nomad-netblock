# nomad-netblock guide

## How it works
- Group `network { mode = "bridge" }` gives the alloc its own network namespace. All rules live in one nft table
  `inet netblock` (IPv4 + IPv6) in that namespace.
- `netblock-init` (prestart, `sidecar = false`, `cap_add = ["net_admin"]`, not privileged): reads the config, fetches
  service targets once (retries up to 30 s), applies the full ruleset atomically, exits 0. The app starts only after
  that. Fail closed: bad config, nft error, or Consul incomplete with `init_require_consul = true` -> deny-all (DNS only
  if configured) and a non-zero exit, so the alloc fails before the app starts.
- `netblock-watch` (poststart, `sidecar = true`, `cap_add = ["net_admin"]`): re-applies the ruleset (keeping the current
  service set), then one Consul blocking query per service on `/v1/health/service/<name>` **without `?passing`**.
  Critical instances are included by default (`include_critical = true`): the app decides health, netblock only decides
  reachability, so a flapping check never cuts the app off before it notices. Sets `svc4`/`svc6` (`ip . port`) are
  replaced atomically (flush + add in one `nft -f`). A target that disappears stays for `removal_grace` (60 s) so
  in-flight failover is not cut. On errors the last good set stays (exponential backoff 1-30 s).
- The app task gets **no** extra caps, so it cannot change the table.

Why the API and not SRV lookups: DNS answers only contain passing instances and are TTL-cached, so the sidecar and the
app would race on failover; the health API with blocking queries sees changes first.

Ruleset order: `lo`, established/related, invalid drop, DNS (if set), Consul endpoints, `@svc4`/`@svc6`, static CIDRs,
IPv6 router solicitations (silent drop, counter `ipv6_rs`), then record dest in dynamic sets `drop4`/`drop6`
(per-element counters, 24 h), counter `would_drop`, rate-limited log `netblock-drop `, then reject (TCP reset /
ICMP admin-prohibited) in `enforce`, or accept in `audit`.

## Config
Typically stored in the Nomad Variable `nomad/jobs/<job>` and rendered with
[examples/netblock.conf.tpl](../examples/netblock.conf.tpl) (only netblock keys are rendered).
Unknown or duplicate keys are errors (fail closed).

| key | default | format / meaning |
|---|---|---|
| `mode` | `enforce` | `enforce` or `audit` (log + count would-be drops, accept them) |
| `allow_cidrs` (`egress_allow` alias) | - | `<tcp\|udp> <ip\|cidr> [port\|lo-hi]`, `;`/`,` separated; `/0` rejected |
| `allow_services` | - | Consul: `name`, `tag.name`, `name@dc`, `tag.name@dc`, comma separated |
| `allow_nomad_services` | - | Nomad native: `name[@namespace]`, comma separated |
| `dns_resolver` | resolv.conf | IPs, or `none` |
| `consul_addrs` (`consul_addr` alias) | - | `ip:port, ...` of Consul HTTPS APIs, with failover (required with `allow_services`) |
| `consul_tls_server_name` | - | TLS name if the IP is not in the cert SANs |
| `consul_ca_file` / `consul_token_file` | `/local/consul-ca.pem`, `/secrets/consul.token` | |
| `include_critical` | `true` | include non-passing instances |
| `removal_grace` | `60s` | Go duration |
| `init_require_consul` | `true` | init fails closed if any service could not be fetched |
| `run_as` | - | `uid[:gid]`: watch drops to this uid with only CAP_NET_ADMIN |
| `nomad_addr`, `nomad_token_file` | Task API socket, `$NOMAD_TOKEN` | overrides for Nomad service discovery |

Example:

```
mode = enforce
allow_cidrs = tcp 203.0.113.10/32 443; udp 198.51.100.0/24 53
allow_services = postgres, redis
consul_addrs = 192.0.2.10:8501, 192.0.2.11:8501
run_as = 65532
```

## Consul auth
Give each job a dedicated read-only token (or use Consul workload identity if your cluster has it). See
[examples/consul-policy.hcl](../examples/consul-policy.hcl). Store the token in a **task-scoped** variable
`nomad/jobs/<job>/<group>/<task>` so only the netblock tasks can read it.

## Several Consul endpoints
Endpoints are tried in order starting at the last one that worked. Connect/TLS errors, timeouts (3 s dial), 5xx and
429 put an endpoint in backoff (5 s doubling to 60 s) and the next one is tried in the same call. 4xx (ACL) is not
retried. When all are in backoff they are still tried as a last resort. One `consul` accept rule is added per endpoint.

## Non-root watch: `run_as`
watch starts as root, re-execs itself as the given uid/gid with an empty group list and CAP_NET_ADMIN as the only
(ambient) capability, forwards signals and returns the child's exit code. init stays root. The Consul accept rules get
`meta skuid <uid>`, so only the watch process can open connections to Consul. The token template then needs
`uid`/`gid` set to that user and `perms = "0400"`.

**Caveat:** skuid is only a real boundary if the app cannot change its uid. If the app runs as root with
CAP_SETUID/SETGID, add `cap_drop = ["setuid", "setgid"]` or run it as a non-root user.

## Nomad native services
`allow_nomad_services` uses blocking queries on `/v1/service/<name>` through the Task API socket
`$NOMAD_SECRETS_DIR/api.sock` (no network egress needed) with the workload identity token (`identity { env = true }`).
Targets merge into the same sets with the same grace and keep-last-good handling.

## Metrics (`:9810/metrics` inside the alloc netns)
`netblock_audit_mode`, `netblock_service_instances{service}`, `netblock_set_elements{set}`, `netblock_graced_elements`,
`netblock_consul_errors_total{service}`, `netblock_consul_last_success_timestamp_seconds{service}`,
`netblock_consul_endpoint_active{endpoint}`, `netblock_consul_endpoint_failures_total`,
`netblock_nft_apply_total`, `netblock_nft_errors_total`, `netblock_would_drop_packets_total`,
`netblock_ipv6_rs_dropped_packets_total`, `netblock_drops_packets_total{proto,dest,service}`.
Drop log line (every 15 s for new packets): `netblock-drop drop|would-drop <proto> <ip:port> service=<name|unknown> packets=N`.

## Limits
- Bridge/CNI groups only; never host network mode.
- The Consul endpoint rule applies to every task in the alloc unless `run_as` is used, so keep the anonymous Consul
  policy minimal.
- Reverse lookup in drop logs only knows allowed services (others show `service=unknown`).
