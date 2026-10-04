# ninja

A single Alpine-based troubleshooting image carrying network diagnostics,
process/filesystem inspection and one client per supported datastore. Built for
"the service is unhealthy, give me a shell that already has the right tools".

```bash
docker pull quay.io/hellodk/ninja:latest
docker run --rm -it --network host quay.io/hellodk/ninja:latest
```

| | |
|---|---|
| Base | `alpine:3.24` |
| Digest | `sha256:1fbe37db9a8af75f58c92968afd6912f716a1a0fb07723a91f9680dd87ad57a2` |
| Size | 167.0 MB compressed (13 layers) / 510 MB uncompressed |
| Findings | **0 OS / 0 application** (Trivy 0.70.0) |
| Default user | `root` — this is a debug image, it needs `CAP_NET_ADMIN`/`CAP_NET_RAW` for `tcpdump` |

Both numbers above were produced by pulling the published digest back from the
registry and re-scanning it, not from the local build.

## Why Alpine

The Debian variants of every tool in this image were measured first. Debian
bookworm carried 256 findings for the Node baseline and 3553 for Go, against 0
for the matching Alpine tags. Every package in this image comes from Alpine
3.24, which was already at zero before any of them were added, so the tool
inventory cost nothing in findings. The price is musl rather than glibc, which
matters if you intend to bind-mount a glibc host binary into it.

## Networking

```
curl  wget  ip  ss  dig  nc  socat  nmap  ngrep  mtr  traceroute
fping  arping  iperf3  tcpdump  tshark  whois  ipcalc  ethtool
bridge-utils  conntrack-tools  iptables  ip6tables  net-tools  nfs-utils
bind-tools  openssl  iputils  iproute2
```

`mtr`, `fping`, `iperf3` and `arping` come from Alpine's `iputils`-adjacent
packages; `tshark` replaces the `wireshark-cli` name, which does not exist on
Alpine.

## Host and process inspection

```
bash  top  htop  iotop  ps  pidstat  iostat  sar  strace  lsof
file  stat  find  grep  sed  awk  vim  nano  tree  ncdu  jq
binutils  procps  psmisc  util-linux  shadow  lm_sensors  pciutils
usbutils  smartmontools  blkid  lsblk  dmesg  nsenter
```

`smartmontools` provides `smartctl`, not a binary named after the package.
`iotop` needs kernel 4.19+ and `sensors` reads `/sys`, so both will report
nothing inside a container without the host's `/sys` mounted.

## Datastore clients

| Store | Client | Version in image | Notes |
|---|---|---|---|
| MySQL / MariaDB | `mysql`, `mariadb` | MariaDB client 15.2 | `mysql` is a deprecated alias that prints a warning; use `mariadb` |
| PostgreSQL | `psql`, `pg_dump`, `pg_restore` | 18.6 | |
| Redis | `redis-cli` | 8.8.0 | |
| Valkey | `valkey-cli` | 9.0.4 | Separate Alpine package from `valkey`, which ships only the server |
| SQLite | `sqlite3` | 3.53.4 | |
| MongoDB / YugabyteDB DocDB | `mongostat`, `mongodump`, `mongoimport`, `mongoexport` | 100.14.1 | Alpine's `mongodb-tools` does not include `mongosh` |
| Aerospike | `libaerospike.so` + `asdb` | C client 7.6.2, built from source | Library only — see below |
| Elasticsearch | `es` wrapper + `py3-elasticsearch` | 7.11.0 | See below |
| YugabyteDB | `yb` wrapper | delegates to `psql` / `mongostat` | See below |

### Aerospike — library, not CLI

Alpine packages no Aerospike client, so the C client is compiled from source in
a build stage and the resulting `libaerospike.so` is copied into the final
image. **There is no Aerospike CLI here.** Upstream `ascli` is a Java tool and
is not packaged for Alpine; the `asdb` wrapper exists to make the gap explicit
and to fall back to a TCP reachability check:

```bash
asdb ping <host>              # TCP reachability on 3000
asdb version                  # what this image actually provides
docker run --rm -it --network <net> aerospike/aerospike-tools ascli -h <host>
```

### Elasticsearch — REST wrapper

Elasticsearch ships no standalone CLI, so `es` wraps the REST API with
`curl` and `jq`:

```bash
es health                      # cluster health
es cat my-index                # index listing
es get my-index 20             # 20 hits
es get my-index '{"query":{"match":{"user":"alice"}}}'
es count my-index
es mapping my-index
es raw GET /_cat/nodes         # escape hatch
```

Point it at a non-default target with `ES_HOST` (full URL or hostname) and
`ES_PORT`; `ES_AUTH=user:pass` and `ES_INSECURE=1` are also honoured.

### YugabyteDB — YSQL via psql, DocDB via mongostat

There is no Alpine `ysqlsh`. YSQL speaks the PostgreSQL wire protocol, so
`psql` is the supported substitute and `yb` builds the connection string:

```bash
yb sql prod-node.corp 5433     # prints postgresql://yugabyte@prod-node.corp:5433/yugabyte
yb psql prod-node.corp -c '\l'
yb docdb prod-node.corp        # prints mongodb://prod-node.corp:5433/yugabyte
```

Override the defaults with `YB_SQL_USER`, `YB_SQL_PORT`, `YB_SQL_DB`,
`YB_DOCDB_PORT`, `YB_DOCDB_DB`.

## Building

```bash
docker build -t ninja:test -f Dockerfile.ninja .
trivy image --scanners vuln ninja:test
```

The build stage pins the Aerospike client with `ARG AEROSPIKE_VERSION=7.6.2`.
The aerospike `make build` is deliberately **not** wrapped in `|| true`: an
earlier revision suppressed the error, produced an empty `/out`, and shipped an
image that claimed Aerospike support and had none. There is now a
`test -n "$(ls -A /out/lib)"` assertion in that stage so the build fails if the
library is missing.

`bin/es`, `bin/yb` and `bin/asdb` are plain POSIX shell and are the only files
this image adds that are not from Alpine.
