# Changelog

All notable changes to this project. Versions follow [semver](https://semver.org); the config map ABI has its own number (`FF_ABI_VERSION`) that `fivemctl` checks on every call.

## [3.0.0] - 2026-10-31

Ground-up rewrite of v2. Same idea, same rough rule set, very little shared code.

### Fixed (bugs present in v2)

- The pipeline ran the blocklist, lockdown and bogon screen before checking whether a packet was even addressed to the protected server, so attaching to a shared interface was not actually safe. Scope now comes first, and the bogon screen, lockdown and strict TCP only apply to game ports.
- The IPv6 bogon screen dropped neighbour discovery from `fe80::` sources, which broke IPv6 on the box. Link-scope IPv6 now always passes.
- Every non-first fragment to the protected address was dropped, which broke fragmented traffic to non-game ports (large DNS answers to the server's resolver, for one). Fragments now inherit their first fragment's verdict.
- Token buckets reset their timestamp on every refill and leaked the fractional token each time. A source sending at 90% of its budget could see half its packets dropped.
- SYN, ICMP and OOB limits were minimum gaps with no burst, so parallel connects from one client got dropped.
- A FIN deleted the flow, so the client's final ACK of a graceful close was dropped as unknown and the server sat in `LAST_ACK` retransmitting.
- The systemd unit passed `${FF_EXTRA}` as one argument, so the documented `--on dry-run` broke the unit.
- `unload` always detached in default mode, which did nothing when the program had fallen back to skb mode, and it would detach anyone's XDP program.
- Numeric options went through bare `strtoull`, so negative values silently wrapped.
- The global ceilings ran through a single spin-locked bucket shared by every CPU.

### Added

- One longest-prefix-match rule table per address family holding both allow and block rules. Allow a /32 inside a blocked /24. IPv6 rules at any prefix length, /128 included.
- Rules persist across `unload`, `reload` and (through the systemd unit) reboots. `save`, `restore`, `restore --as block` for plain lists, and `reap` with a one-minute timer.
- `/etc/fivem-filter.conf` and `fivemctl reload` for live reconfiguration from the file.
- Per-class burst settings: `burst`, `syn-burst`, `icmp-burst`, `oob-burst`.
- Up to four `aux-port`s and port ranges written as `30120-30129`.
- Byte counters next to packet counters, a `not protected` counter, `stats --json`, `list --json`, `log --json`, `log --reason`.
- `fivemctl exporter`, a Prometheus endpoint on localhost.
- ABI version check between `fivemctl` and the loaded program.
- Refusal to replace a foreign XDP program without `--force`.
- More amplification source ports: TFTP, SLP, CoAP, DVR discovery.
- Fuller IPv6 bogon list: ULA, discard prefix, v4-mapped, `3fff::/20`.
- Test suite: unit tests for the bogon tables, token bucket and parsers; 106 packet tests that run crafted frames through the real program with `BPF_PROG_TEST_RUN`; and an end-to-end test that attaches to a veth pair and drives every `fivemctl` command. All of it runs in CI on every push.

### Changed

- Minimum kernel is 5.15 (BPF global functions with pointer args). The pipeline is split into global subprograms so the verifier checks each one on its own. Fully inlined, it ran past the verifier's one million instruction budget.
- Lockdown only applies to game ports. You can no longer lock yourself out of SSH with it.
- Pin directory is still `/sys/fs/bpf/fivem-filter`, but the map set changed. v2 pins have to go before v3 loads; see [docs/MIGRATING.md](docs/MIGRATING.md).

## [3.0.0-beta.1] - 2026-10-31

Control plane rewrite. Feature complete, pending docs and packaging.

## [3.0.0-alpha.1] - 2026-10-31

Data plane rewrite, passing the verifier and the packet test suite.

[3.0.0]: https://github.com/valerisn/fivem-filter-v3/releases/tag/v3.0.0
[3.0.0-beta.1]: https://github.com/valerisn/fivem-filter-v3/releases/tag/v3.0.0-beta.1
[3.0.0-alpha.1]: https://github.com/valerisn/fivem-filter-v3/releases/tag/v3.0.0-alpha.1
