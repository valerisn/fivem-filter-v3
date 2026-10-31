# Contributing

The kernel side can't be debugged by printf on a box that's being flooded, so the bar here is tests.

## Layout

`src/bpf/` is the XDP program, split into headers by pipeline stage, with `filter.bpf.c` tying it together. `src/shared/` holds what both sides compile: the map ABI, the bogon tables and the token bucket. Keep those free of BPF helpers so the unit tests can include them. `src/ctl/` is `fivemctl`. `util.c` stays libbpf-free for the same reason.

## Before you push

```bash
make test               # unit tests, no root
sudo make verify        # your kernel's verifier
sudo make test-xdp      # packet tests through the real program
sudo tests/e2e.sh       # veth + netns, every fivemctl command
```

CI runs all four on every push. A change to a drop rule should come with a packet test that shows it dropping what it should and passing what it shouldn't. A change to `bogon.h` gets edge cases on both sides of every range it touches.

## Things that will bite you

The verifier budget is real. The pipeline is split into global subprograms (`FF_SUBPROG`) for that reason, and anything with a lot of branches belongs in one. Global functions only take scalars, `ctx`, or pointers to structs made entirely of scalars, which is why `ff_l3` carries offsets rather than packet pointers. Read everything you need from the packet before the first subprogram call; depending on the kernel, packet pointers may not survive it.

`ff_config` and every other struct in `ff_abi.h` is ABI. Changing layout means bumping `FF_ABI_VERSION`. Stats are append-only, and the first three entries have to stay pass reasons.

No helper calls while holding a `bpf_spin_lock`.

## Commits

Small, one change each, message saying why. The history doubles as the design notes.
