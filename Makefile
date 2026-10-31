# SPDX-License-Identifier: GPL-2.0-only
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 3.0.0-dev)

CLANG      ?= clang
CC         ?= cc
BPFTOOL    ?= bpftool
LLVM_STRIP ?= llvm-strip
PREFIX     ?= /usr/local
SYSCONFDIR ?= /etc
UNITDIR    ?= /etc/systemd/system
LIBDIR     := $(PREFIX)/lib/fivem-filter

ARCH := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/;s/ppc64le/powerpc/;s/mips.*/mips/;s/riscv64/riscv/')

BUILD := build

# The multiarch include dir is where Debian/Ubuntu hide asm/types.h. Without
# it clang -target bpf can't find half of linux/*.h.
BPF_CFLAGS := -O2 -g -Wall -Werror -target bpf -D__BPF__ -D__TARGET_ARCH_$(ARCH) \
              -Isrc/shared -I/usr/include/$(shell uname -m)-linux-gnu \
              $(EXTRA_BPF_CFLAGS)

CFLAGS  ?= -O2 -g
CFLAGS  += -Wall -Wextra -Wno-unused-parameter -Wshadow -std=gnu11 \
           -Isrc/shared -Isrc/ctl -DFF_VERSION='"$(VERSION)"' \
           -DFF_LIBDIR='"$(LIBDIR)"'
LDLIBS  := -lbpf -lelf -lz

BPF_OBJ := $(BUILD)/filter.bpf.o
CTL     := $(BUILD)/fivemctl

SHARED_H := $(wildcard src/shared/*.h)
CTL_SRC  := $(wildcard src/ctl/*.c)
CTL_H    := $(wildcard src/ctl/*.h)
CTL_OBJ  := $(patsubst src/ctl/%.c,$(BUILD)/ctl/%.o,$(CTL_SRC))

UNIT_TESTS := $(patsubst tests/unit/%.c,$(BUILD)/tests/%,$(wildcard tests/unit/test_*.c))

.PHONY: all bpf ctl test test-unit test-xdp verify check-deps install uninstall clean dist

all: bpf ctl

bpf: $(BPF_OBJ)
ctl: $(CTL)

$(BUILD) $(BUILD)/ctl $(BUILD)/tests:
	@mkdir -p $@

$(BPF_OBJ): src/bpf/filter.bpf.c $(SHARED_H) | $(BUILD)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@# drop DWARF, keep BTF - the verifier needs BTF for the spin locks
	@$(LLVM_STRIP) -g $@ 2>/dev/null || true

$(BUILD)/ctl/%.o: src/ctl/%.c $(SHARED_H) $(CTL_H) | $(BUILD)/ctl
	$(CC) $(CFLAGS) -c $< -o $@

$(CTL): $(CTL_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

# ------------------------------------------------------------------- tests

test: test-unit

# Pure arithmetic, no root, no kernel, no libbpf.
test-unit: $(UNIT_TESTS)
	@set -e; for t in $(UNIT_TESTS); do $$t; done

$(BUILD)/tests/%: tests/unit/%.c tests/unit/check.h $(SHARED_H) | $(BUILD)/tests
	$(CC) -O2 -g -Wall -Wextra -Isrc/shared -Itests/unit $< -o $@

# Runs crafted packets through the real program with BPF_PROG_TEST_RUN.
# Needs root (or CAP_BPF + CAP_NET_ADMIN) but never touches an interface.
$(BUILD)/tests/test_xdp: tests/xdp/test_xdp.c tests/xdp/pkt.h $(SHARED_H) | $(BUILD)/tests
	$(CC) $(CFLAGS) -Itests/xdp $< -o $@ $(LDLIBS)

test-xdp: $(BPF_OBJ) $(BUILD)/tests/test_xdp
	$(BUILD)/tests/test_xdp $(BPF_OBJ)

# Load into the kernel and throw it away. Catches verifier rejections.
verify: $(BPF_OBJ)
	@rm -f /sys/fs/bpf/ff-verify
	$(BPFTOOL) prog load $(BPF_OBJ) /sys/fs/bpf/ff-verify type xdp
	@$(BPFTOOL) prog show pinned /sys/fs/bpf/ff-verify
	@rm -f /sys/fs/bpf/ff-verify
	@echo "verifier OK"

check-deps:
	@command -v $(CLANG) >/dev/null || { echo "missing: clang"; exit 1; }
	@echo '#include <bpf/libbpf.h>' | $(CC) -E - >/dev/null 2>&1 || \
		{ echo "missing: libbpf-dev (>= 0.8)"; exit 1; }
	@echo '#include <gelf.h>' | $(CC) -E - >/dev/null 2>&1 || \
		{ echo "missing: libelf-dev"; exit 1; }
	@echo "dependencies OK"

# ----------------------------------------------------------------- install

install: all
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(LIBDIR) $(DESTDIR)$(UNITDIR)
	install -m 0755 $(CTL) $(DESTDIR)$(PREFIX)/bin/fivemctl
	install -m 0644 $(BPF_OBJ) $(DESTDIR)$(LIBDIR)/filter.bpf.o
	install -m 0644 systemd/fivem-filter.service $(DESTDIR)$(UNITDIR)/
	install -m 0644 systemd/fivem-filter-reap.service $(DESTDIR)$(UNITDIR)/
	install -m 0644 systemd/fivem-filter-reap.timer $(DESTDIR)$(UNITDIR)/
	@# never stomp an existing config, people tune these by hand
	@if [ ! -e $(DESTDIR)$(SYSCONFDIR)/fivem-filter.conf ]; then \
		install -D -m 0644 packaging/fivem-filter.conf \
			$(DESTDIR)$(SYSCONFDIR)/fivem-filter.conf; \
	else echo "keeping existing $(SYSCONFDIR)/fivem-filter.conf"; fi

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/fivemctl
	rm -rf $(DESTDIR)$(LIBDIR)
	rm -f $(DESTDIR)$(UNITDIR)/fivem-filter.service
	rm -f $(DESTDIR)$(UNITDIR)/fivem-filter-reap.service
	rm -f $(DESTDIR)$(UNITDIR)/fivem-filter-reap.timer

dist: all
	@rm -rf $(BUILD)/dist && mkdir -p $(BUILD)/dist/fivem-filter-$(VERSION)
	cp $(CTL) $(BPF_OBJ) README.md LICENSE CHANGELOG.md $(BUILD)/dist/fivem-filter-$(VERSION)/
	cp -r systemd packaging $(BUILD)/dist/fivem-filter-$(VERSION)/
	tar -C $(BUILD)/dist -czf $(BUILD)/fivem-filter-$(VERSION)-$(shell uname -m).tar.gz \
		fivem-filter-$(VERSION)

clean:
	rm -rf $(BUILD)
