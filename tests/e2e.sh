#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# End to end: real attach on a veth, real packets from a netns, every
# fivemctl command. Needs root, iproute2, python3, jq, curl.
#
#   sudo tests/e2e.sh
#
# Throwaway names and addresses only; cleans up after itself even on failure.
set -euo pipefail

CTL=${CTL:-build/fivemctl}
OBJ=${OBJ:-build/filter.bpf.o}
NS=ffe2e
SRV=45.90.12.10
PEER=45.90.12.20
BOGON=10.9.9.9
PORT=30120
TMP=$(mktemp -d)
fails=0
checks=0

cleanup() {
	"$CTL" unload --purge >/dev/null 2>&1 || true
	ip netns del "$NS" 2>/dev/null || true
	ip link del ffe0 2>/dev/null || true
	[[ -n "${EXP_PID:-}" ]] && kill "$EXP_PID" 2>/dev/null || true
	rm -rf "$TMP"
}
trap cleanup EXIT

ok()   { checks=$((checks + 1)); echo "  ok   $*"; }
bad()  { checks=$((checks + 1)); fails=$((fails + 1)); echo "  FAIL $*"; }
check() { local what=$1; shift; if "$@"; then ok "$what"; else bad "$what"; fi; }

# packets from the netns side, optionally from a specific source address
send() { # send SRC COUNT [PAYLOAD]
	ip netns exec "$NS" python3 - "$1" "$2" "${3:-hello}" "$SRV" "$PORT" <<'PY'
import socket, sys
src, n, payload, dst, port = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], int(sys.argv[5])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((src, 0))
for _ in range(n):
    s.sendto(payload.encode('latin1'), (dst, port))
PY
	sleep 0.2
}

counter() { "$CTL" stats --json | jq ".counters.$1.packets"; }

echo "== setup"
cleanup
ip netns add "$NS"
ip link add ffe0 type veth peer name ffe1
ip link set ffe1 netns "$NS"
ip addr add "$SRV/24" dev ffe0
ip link set ffe0 up
ip -n "$NS" addr add "$PEER/24" dev ffe1
ip -n "$NS" addr add "$BOGON/32" dev ffe1
ip -n "$NS" link set ffe1 up
ip -n "$NS" link set lo up
# ping once so ARP is settled before the filter goes on
ip netns exec "$NS" ping -c1 -W2 "$SRV" >/dev/null

echo "== load"
check "status says not loaded" bash -c "! '$CTL' status >/dev/null"
"$CTL" load -i ffe0 --ip "$SRV" --port "$PORT" --mode skb --grace 0 --obj "$OBJ" --log-sample 1
check "status works once loaded" "$CTL" status
check "second load is refused" bash -c "! '$CTL' load -i ffe0 --ip $SRV --obj $OBJ 2>/dev/null"
check "version" "$CTL" version

echo "== traffic"
before=$(counter pass)
send "$PEER" 5
check "player traffic passes" test "$(counter pass)" -ge $((before + 5))

before=$(counter bogon)
send "$BOGON" 3
check "bogon source dropped" test "$(counter bogon)" -ge $((before + 3))

before=$(counter udp_size)
send "$PEER" 1 "$(python3 -c 'print("x"*1450)')"
check "oversize payload dropped" test "$(counter udp_size)" -ge $((before + 1))

echo "== rules"
"$CTL" block "$PEER" >/dev/null
before=$(counter blocklist)
send "$PEER" 2
check "blocked source dropped" test "$(counter blocklist)" -ge $((before + 2))
check "list shows the block" bash -c "'$CTL' list block | grep -q '$PEER'"
check "unallow on a block rule is refused" bash -c "! '$CTL' unallow $PEER 2>/dev/null"
"$CTL" unblock "$PEER" >/dev/null
before=$(counter pass)
send "$PEER" 2
check "unblocked source passes again" test "$(counter pass)" -ge $((before + 2))

"$CTL" allow "$BOGON" >/dev/null
before=$(counter allowlist)
send "$BOGON" 2
check "allowlist beats bogon screen" test "$(counter allowlist)" -ge $((before + 2))
"$CTL" unallow "$BOGON" >/dev/null

"$CTL" block 203.0.113.0/24 --ttl 1s >/dev/null
sleep 2
check "reap removes expired rule" bash -c "'$CTL' reap | grep -q 'reaped 1'"

"$CTL" block 198.51.100.0/24 >/dev/null
"$CTL" block 2001:db8:dead::/48 --ttl 1h >/dev/null
"$CTL" save "$TMP/rules" >/dev/null
check "save wrote both rules" test "$(grep -c '^block' "$TMP/rules")" -eq 2
"$CTL" restore "$TMP/rules" --replace >/dev/null
check "restore round-trips" test "$("$CTL" list --json | jq length)" -eq 2
printf '1.1.1.0/24\n# comment\n8.8.8.8\n' > "$TMP/plain"
"$CTL" restore "$TMP/plain" --as block >/dev/null
check "plain list import" test "$("$CTL" list --json | jq length)" -eq 4

echo "== config"
"$CTL" config --pps 123 --on dry-run >/dev/null
check "live config change" bash -c "'$CTL' config | grep -q '123/s'"
before=$(counter dry_run)
send "$BOGON" 2
check "dry-run passes but counts" test "$(counter dry_run)" -ge $((before + 2))
cat > "$TMP/conf" <<EOF
# test config
ip = $SRV
port = $PORT
pps = 321
on = log
EOF
"$CTL" reload --config "$TMP/conf" >/dev/null
check "reload from file" bash -c "'$CTL' config | grep -q '321/s'"
check "reload resets dry-run to file's view" bash -c "! '$CTL' config | grep -q dry-run"
check "bad config is rejected" bash -c "echo 'pps = lots' > $TMP/bad; ! '$CTL' reload --config $TMP/bad 2>/dev/null"

echo "== exporter"
"$CTL" exporter --listen 127.0.0.1:19273 2>/dev/null &
EXP_PID=$!
sleep 0.5
curl -fsS http://127.0.0.1:19273/metrics > "$TMP/metrics"
check "exporter up" grep -q '^fivem_filter_up 1' "$TMP/metrics"
check "exporter counts rules" grep -q 'fivem_filter_rules{action="block"} 4' "$TMP/metrics"
check "exporter 404s elsewhere" bash -c "! curl -fsS http://127.0.0.1:19273/nope >/dev/null 2>&1"
kill "$EXP_PID"; wait "$EXP_PID" 2>/dev/null || true; EXP_PID=

echo "== unload"
"$CTL" unload >/dev/null
check "status says not loaded after unload" bash -c "! '$CTL' status >/dev/null"
"$CTL" load -i ffe0 --ip "$SRV" --mode skb --obj "$OBJ" >/dev/null
check "rules survived unload + load" test "$("$CTL" list --json | jq length)" -eq 4
"$CTL" unload --purge >/dev/null
check "purge removes rule pins" test ! -e /sys/fs/bpf/fivem-filter/rules4

echo
echo "e2e            $((checks - fails))/$checks passed"
[[ $fails -eq 0 ]]
