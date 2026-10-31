# Security

If you find a way to get traffic past the filter that it claims to stop, crash or wedge the program, or make `fivemctl` do something it shouldn't as root, please report it privately through GitHub's security advisory form on this repository rather than opening an issue. A bypass published before it's fixed is a free attack tool for every server running this.

Include the kernel version, the output of `fivemctl status`, and ideally a packet test (see `tests/xdp/test_xdp.c`) that shows the problem.

Out of scope: volumetric floods that saturate the uplink before reaching the host. Nothing running on the host can fix those.
