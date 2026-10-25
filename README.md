# nomad-netblock

Egress default-deny firewall for [Nomad](https://www.nomadproject.io/) bridge-mode jobs. A small Go program
(stdlib only) that applies nftables rules inside an allocation's network namespace, with allow sets driven by
Consul or Nomad native service discovery.

Two modes, same binary:

- `netblock init [conf]` (prestart task, `sidecar = false`): applies the full ruleset once (static CIDRs plus
  service targets fetched once) and exits 0. On bad config it applies deny-all (DNS only, if configured) and exits
  non-zero, so the app never starts open.
- `netblock watch [conf]` (poststart sidecar): blocking queries on Consul `/v1/health/service/<name>` and/or Nomad
  `/v1/service/<name>`, atomic nft set updates, 60 s removal grace, drop logs, Prometheus metrics. A discovery error
  keeps the last good set; it never opens the policy.

Default config path: `/local/netblock.conf`. Full guide: [docs/guide.md](docs/guide.md).
Example job, Consul ACL policy and config template: [examples/](examples/).

## Client prerequisite

The Nomad Docker driver plugin's `allow_caps` **must include `net_admin`** on every client that runs netblock tasks:

```hcl
plugin "docker" {
  config {
    allow_caps = ["audit_write", "chown", "dac_override", "fowner", "fsetid", "kill", "mknod",
                  "net_bind_service", "setfcap", "setgid", "setpcap", "setuid", "sys_chroot", "net_admin"]
  }
}
```

Only the netblock tasks get `cap_add = ["net_admin"]`; never run them privileged, and never give the app task that cap.

## Build and test (Linux)

```sh
go vet ./... && go test -race ./...
sudo NETBLOCK_NFT_IT=1 unshare -n go test -run Integration ./...   # real nft test
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=0.3.2" -o netblock-linux-amd64 .
docker build --build-arg VERSION=0.3.2 -t nomad-netblock:0.3.2 .
```

## License

MIT, see [LICENSE](LICENSE).
