# Changelog

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
