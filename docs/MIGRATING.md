# Migrating from v2

v3 pins a different set of maps under the same directory, and its config map layout is incompatible, so the two can't be swapped live. Plan for a few seconds without filtering.

## 1. Export your v2 lists

v2 has no save command, so scrape `list`. This keeps permanent entries and drops TTL'd ones, which would have expired soon anyway:

```bash
sudo fivemctl list block | awk '/permanent/ {print $1}' | sed 's|/64$||' > /root/v2-block.txt
sudo fivemctl list allow | awk '/permanent/ {print $1}' | sed 's|/64$||' > /root/v2-allow.txt
```

v2 printed IPv6 entries as their /64 prefix. The `sed` strips the suffix, which turns them into single /128 rules in v3. If you meant the whole /64, edit the file and put `/64` back.

## 2. Unload v2

```bash
sudo systemctl disable --now fivem-filter     # if you used the v2 unit
sudo fivemctl unload -i eth0                  # v2 binary, still installed
ls /sys/fs/bpf/fivem-filter 2>/dev/null       # should be gone
```

If the directory lingers, remove it with `sudo rm -rf /sys/fs/bpf/fivem-filter`. Unlinking a pin can't hurt anything once the program is detached.

## 3. Install v3

```bash
make && sudo make install
```

This overwrites `/usr/local/bin/fivemctl` and installs the new units. It won't touch an existing `/etc/fivem-filter.conf`.

## 4. Move your settings

`/etc/default/fivem-filter` is gone. Carry its values into `/etc/fivem-filter.conf`:

| v2 | v3 |
|---|---|
| `FF_IFACE=eth0` | `interface = eth0` |
| `FF_IP=...` | `ip = ...` |
| `FF_PORT=30120` | `port = 30120` |
| `FF_EXTRA=--aux-port 40120` | `aux-port = 40120` |
| `FF_EXTRA=--on dry-run` | `on = dry-run` |
| `--pps N` | `pps = N` |

Every v2 option kept its name. The new ones are mostly bursts (`burst`, `syn-burst`, `icmp-burst`, `oob-burst`) because those limits are now token buckets. `syn-rate` means "per second, on average" instead of "minimum gap", so the same number is more permissive in v3. Lower it if you were relying on the old strictness.

`grace` and `flow-idle` take durations now (`30s`, `2m`), and plain numbers still mean seconds.

## 5. Load and restore

```bash
sudo systemctl enable --now fivem-filter fivem-filter-reap.timer
sudo fivemctl restore /root/v2-block.txt --as block
sudo fivemctl restore /root/v2-allow.txt --as allow
sudo fivemctl list
```

Start in dry-run even if v2 ran without it. The scope and port-only changes mean v3 drops less than v2 in some places, and the bursts mean it drops less in others. Watch a busy evening before you trust it.

## Behaviour you might notice

Traffic to ports other than the game ports no longer goes through the bogon screen, lockdown or strict TCP. If you relied on lockdown to close SSH, put a real firewall on SSH instead.

Blocked sources are blocked on every port of the protected address, as before. Allowlisted sources still skip everything.

An allow rule no longer beats a block rule automatically. The more specific prefix wins. If you had the same address on both lists in v2, v3 keeps whichever you restore last.
