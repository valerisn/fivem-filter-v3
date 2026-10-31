# fivem-filter v3

An XDP/eBPF packet filter for FiveM and RedM (CFX) game servers. It runs in the NIC driver before the kernel allocates an `sk_buff`, so a dropped packet costs a few hundred nanoseconds instead of a trip through the network stack.

It does not replace upstream scrubbing. A flood that saturates your uplink is lost before any packet reaches your kernel. This handles everything that does arrive: SYN floods, garbage aimed at the game port, reflected amplification, spoofed martians, fragment abuse, and the CFX `getinfo`/`getstatus` floods that turn one small request into a large reply.

v3 is a ground-up rewrite of [fivem-filter-v2](https://github.com/valerisn/fivem-filter-v2). See [what changed](#whats-new-in-v3) and [docs/MIGRATING.md](docs/MIGRATING.md).

## Quick start

```bash
sudo apt install clang llvm libbpf-dev libelf-dev zlib1g-dev build-essential
make
sudo make install

sudo editor /etc/fivem-filter.conf        # interface, ip, port
sudo systemctl enable --now fivem-filter fivem-filter-reap.timer
fivemctl stats --watch 2
```

The shipped config starts in **dry-run**: every rule fires, gets counted and logged, and the packet goes through anyway. Leave it like that through a busy evening. If `fivemctl stats` only shows drops you are happy to lose, remove `on = dry-run` and `systemctl reload fivem-filter`. Skipping this step is how people firewall their own player base.

Without systemd:

```bash
sudo fivemctl load -i eth0 --ip 203.0.113.10 --port 30120 --on dry-run
```

## Requirements

Linux 5.15 or newer (the pipeline uses BPF global functions with pointer arguments, which landed in 5.12; 5.15 is the oldest LTS that has them), clang 11+, libbpf 0.8+ with libelf and zlib. Any NIC works. Drivers without native XDP fall back to generic mode automatically, which still filters but loses most of the speed advantage.

`make check-deps` checks the toolchain. `make test` runs the unit tests with no root and no kernel. `sudo make verify` pushes the program through your kernel's verifier and unloads it again, and `sudo make test-xdp` runs the packet test suite against your kernel without touching any interface.

## How a packet is judged

Every packet takes the same path and the first decision wins.

1. **Parse** Ethernet, up to two VLAN tags, then IPv4 or IPv6 including a bounded walk of extension headers. Non-IP traffic passes untouched. Lengths come from the IP header, never from the frame size, because frames under 60 bytes arrive padded.
2. **Link-scope IPv6** (neighbour discovery, router advertisements, MLD) always passes. It cannot come from the internet, and dropping it takes the box offline on IPv6.
3. **Scope.** Traffic not addressed to the protected IP passes untouched, so attaching to a shared interface is safe.
4. **Rules.** One longest-prefix-match table per address family holds both allow and block rules, so a single allowed /32 inside a blocked /24 does what you expect. Allow skips every later check. Block drops everything to the protected address, on any port.
5. **Land attacks** (source equals destination) and, optionally, **IP options**.
6. **Fragments.** Only the first fragment carries ports, so it goes through the full pipeline and its verdict is remembered for a couple of seconds. Every later fragment of the same datagram inherits that verdict. A fragment whose first fragment never arrived is dropped. In v2 every non-first fragment was dropped, which quietly broke large DNS answers to the server's own resolver.
7. **Protocol checks**, but only on the game ports. Everything else on the box (SSH, the panel, DNS replies, cloud metadata) is out of reach of the bogon screen, lockdown and strict TCP.

### Game ports, UDP

Lockdown, then the bogon screen, then: oversized packets from known reflection source ports (DNS, NTP, memcached, CLDAP, SSDP, SLP, CoAP and more) are dropped, payloads outside `udp-min`/`udp-max` are dropped, and packets starting with `0xFFFFFFFF` (CFX out-of-band: `getinfo`, `getstatus`, `connect`, `rcon`) go through their own per-source bucket plus a box-wide ceiling. Everything else spends a token from the per-source packet bucket.

### Game ports, TCP

Illegal flag combinations (null, xmas, SYN+FIN, SYN+RST, FIN without ACK) are dropped, and so is a bare SYN carrying payload. New connections pass a box-wide SYN ceiling, a per-source SYN bucket and a per-source new-connection quota per minute. Established traffic must match a flow; in strict mode an unknown non-SYN packet is dropped, which kills ACK floods. A FIN marks the flow as closing rather than deleting it, so the final ACK of a graceful close still matches.

Connections that existed before the filter loaded have no flow entry, so for `grace` seconds after a load (30 by default) unknown flows are adopted instead of dropped. Loading the filter on a live server does not disconnect anyone.

### ICMP

Echo goes through its own per-source bucket and the bogon screen. Everything else (fragmentation needed, unreachables, time exceeded) is only rate limited, because TCP needs it and plenty of ISP routers send it from private addresses. `--on drop-icmp` if you really want none of it.

## Rate limiting

Every per-source limit is a token bucket with a rate and a burst, keyed on the IPv4 address or the IPv6 /64. In v2 the SYN, ICMP and OOB limits were minimum gaps between packets, so a joining client opening a few HTTP connections at once (our observation of client behaviour, not a documented protocol detail) had all but the first SYN dropped and waited a second for the retransmit.

Per-source state lives in a fixed array of 131072 slots allocated at load, not an LRU hash. The memory footprint is known up front, nothing is evicted at the moment it matters, and array values can carry a spin lock, which a token bucket needs on a multi-queue NIC. Colliding sources are detected by fingerprint and reset the slot instead of throttling each other. The hash seed is randomised on every load.

Per-source limits do nothing against spoofed sources. That is what `global-syn-pps` and `global-oob-pps` are for. They run as per-CPU buckets that each get `pps / ncpu`, with no shared lock for every core to fight over during exactly the flood they exist to absorb.

## fivemctl

```
fivemctl load -i IFACE --ip ADDR [--config FILE] [settings]
fivemctl unload [-i IFACE] [--purge] [--force]
fivemctl reload [--config FILE]           re-apply the config file, live
fivemctl status
fivemctl config [settings]                show, or change only what you name
fivemctl stats [--watch [SEC]] [--json] [--all] [--reset]
fivemctl block|allow ADDR|CIDR... [--ttl 1h]
fivemctl unblock|unallow ADDR|CIDR...
fivemctl list [block|allow] [--json]
fivemctl reap                             delete expired rules
fivemctl save FILE
fivemctl restore FILE|- [--replace] [--as block|allow]
fivemctl log [--json] [--reason KEY]      stream sampled drops
fivemctl exporter [--listen 127.0.0.1:9273]
```

Every setting has the same name as a command-line flag and as a config-file key. `fivemctl help` prints the full list straight from the table the parser uses, so the help cannot drift from the code.

```bash
fivemctl config --pps 400 --syn-burst 32
fivemctl block 198.51.100.0/24 --ttl 6h
fivemctl allow 192.0.2.44                    # staff, server list crawlers
curl -s https://example.com/bad.txt | fivemctl restore - --as block
fivemctl log --reason bogon
```

Rules survive `unload` and `reload`, and the systemd unit saves them on stop and restores them on start, so bans survive reboots too. Expired rules stop matching immediately and the reap timer deletes them every minute. `unload --purge` drops everything.

`load` refuses to replace an XDP program it did not attach unless you pass `--force`, and `unload` only detaches the program id it loaded, in the mode it actually attached with.

### Settings

| Setting | Default | Controls |
|---|---|---|
| `interface` / `-i` | none | Interface to attach to. |
| `ip` / `ip6` | any / none | Protected address, as the NIC sees it. On most clouds that is the private interface address. |
| `port` | 30120 | Game port, or a range like `30120-30129`. |
| `aux-port` | none | Up to four extra ports with the same treatment, e.g. txAdmin on 40120. |
| `pps` / `burst` | 200 / 60 | Per-source packet bucket on game ports. |
| `syn-rate` / `syn-burst` | 5 / 16 | Per-source new TCP connections. |
| `icmp-rate` / `icmp-burst` | 1 / 4 | Per-source ICMP echo. |
| `oob-rate` / `oob-burst` | 1 / 3 | Per-source `getinfo`/`getstatus`. |
| `conn-per-min` | 60 | New TCP connections per minute per source. 0 disables. |
| `global-syn-pps` | 20000 | Box-wide SYN ceiling. 0 disables. |
| `global-oob-pps` | 2000 | Box-wide OOB ceiling. 0 disables. |
| `amp-limit` | 512 | Bytes above which known reflection source ports are dropped. |
| `udp-min` / `udp-max` | 1 / 1400 | Accepted UDP payload on game ports. |
| `flow-idle` | 2m | TCP flow idle timeout. |
| `frag-ttl` | 2s | How long a first fragment's verdict applies to the rest. |
| `log-sample` | 256 | Log one drop in N. 0 disables. |
| `grace` | 30s | How long pre-existing TCP flows get adopted after a load. |
| `mode` | auto | `native`, `skb` or `hw`. Auto tries native, falls back to skb. |

Durations take `s`, `m`, `h`, `d` or `w`. Numbers are checked strictly: `--pps -1` is an error, not 18 quintillion.

### Flags

Toggled with `--on NAME` / `--off NAME` (comma separated works), or `on = a, b` in the config file.

| Flag | Default | Effect |
|---|---|---|
| `enabled` | on | Master switch. Off passes everything. |
| `dry-run` | off | Count and log drops but pass the packet. |
| `bogon` | on | Drop unroutable sources on game ports. |
| `strict-tcp` | on | Non-SYN TCP on game ports needs a known flow. |
| `log` | on | Emit sampled drop events. |
| `drop-icmp` | off | Drop all ICMP instead of rate limiting it. |
| `drop-ipv6` | off | Drop IPv6 to the protected address. Link-scope IPv6 still passes. |
| `drop-frags` | off | Drop every fragment, the first included. |
| `drop-ip-opts` | off | Drop packets carrying IP options. |
| `drop-oob` | off | Drop all OOB queries. This delists you from server browsers. |
| `lockdown` | off | Game ports accept allowlisted sources only. Emergency use. SSH and everything else on the box are unaffected. |

## Observability

```
$ fivemctl stats --watch 2
counter                                       packets        bytes          pps          bps
pass                                           18.29M        2.11G      41220.5       38.10M
per-source packet rate                          9.91M      614.55M       8801.0        4.37M
global syn ceiling                              1.20M       72.27M       1980.0      950.40k
udp amplification source port                 330.22k      425.98M        410.5        4.24M
```

Counters are per-CPU, carry both packets and bytes, and are summed on read so the fast path never contends on them. `--json` gives machine-readable output, and the keys match the `reason` labels the exporter uses.

`fivemctl exporter` serves Prometheus metrics (`fivem_filter_packets_total`, `fivem_filter_bytes_total`, `fivem_filter_rules`, `fivem_filter_dry_run` and friends). It binds to localhost by default; publishing counters of what you drop to the internet you drop it from helps nobody but the attacker. `systemctl enable --now fivem-filter-exporter` runs it as a service.

`fivemctl log` streams sampled drops with addresses, ports and reason. It is the quickest way to find out whether a rule catches what you think it catches.

## Tuning notes

**Start in dry-run and read the numbers.** The defaults assume a busy server with normal players. Watch `per-source packet rate` and `per-source syn rate` at peak before you commit.

**`conn-per-min` is the limit people trip over.** A player reconnecting in a loop or a server list crawler can exceed it legitimately. Allowlist known crawlers instead of raising it for everyone.

**Global ceilings belong well above your real peak.** They exist to cap a flood, not to shape normal traffic.

**`oob-rate 1` slows how fast you appear in server browsers.** That is usually the right trade, since query traffic is the cheapest attack surface a FiveM server has.

**On cloud hosts, set `ip` to the interface address.** If the protected address never matches, everything shows up under `not protected` and nothing is filtered.

## Limitations

XDP is ingress only, so nothing here shapes outbound traffic. There is no reassembly; fragments are judged, not buffered, and a trailing fragment that arrives before its first fragment is dropped. Hardware offload mode is accepted but will not verify on real NICs, because the map set is far beyond what offload engines support. The flow table holds 512K entries in LRU order, so past that the oldest flows get evicted and their next packet counts as unknown. Rule hit counters are sampled (1 in 64) to avoid every core bouncing one cacheline on a hot rule, so treat them as approximate. An expired rule keeps shadowing a broader live rule underneath it until the next reap, which runs every minute.

## What's new in v3

The pipeline checks scope first, so blocklists, the bogon screen and lockdown no longer touch traffic for other addresses or other ports. IPv6 neighbour discovery no longer gets eaten by the bogon screen. Fragments inherit their first fragment's verdict instead of being dropped wholesale. Allow and block rules share one longest-prefix table per family, IPv6 CIDRs work at any length, and rules survive reloads and reboots. SYN, ICMP and OOB limits are real token buckets with bursts, and all buckets keep their fractional remainder instead of leaking it on every refill. Global ceilings are per-CPU and lock-free. Graceful TCP closes no longer get their final ACK dropped. Counters carry bytes. There is a config file with live reload, JSON output everywhere, a Prometheus exporter, an ABI version check between `fivemctl` and the loaded program, and a test suite that runs crafted packets through the real program on a real kernel in CI. [CHANGELOG.md](CHANGELOG.md) has the full list.

## License

GPL-2.0-only. The BPF program has to be GPL to use the kernel's GPL-only helpers, and the rest follows for simplicity.
