# Copyright 2026 Cryptsoft Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# TrustZone test tools built here. The CTAP2-level TrustZone suite lives
# in the in-tree Rust client as examples of pqf-ctaphid:
#
#   cargo run -p pqf-ctaphid --example tz_test --target $(HOST) -- [flags]
#   cargo run -p pqf-ctaphid --example tz_cm   --target $(HOST) -- [flags]
#
# tz_test    -- the TrustZone-specific suite (presence gate, signature
#              counter, resident credentials, ClientPIN, raw button
#              probes).
# tz_cm      -- credMgmt enumeration with status bytes; --wipe clears the
#              store. The TrustZone port has no authenticatorReset, and
#              its credential store survives reflashing, so this is how
#              a bench board is returned to a known state.
#
# What is built HERE, against the in-tree c/hid transport only:
#
# tz_transport -- CTAPHID multi-frame reassembly, via pqhid.
#
# The broad CTAP2 conformance surface is an external conformance
# suite's job; the tools above cover what such a suite cannot reach
# because it is specific to the TrustZone build. No third-party FIDO
# library is used anywhere here, deliberately.

PQHID  ?= ../../c/hid
HOST   := $(shell rustc -vV | awk '/^host:/{print $$2}')

CFLAGS  += -O2 -Wall -Wextra -std=c11
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
FRAMEWORKS := -framework IOKit -framework CoreFoundation
else
FRAMEWORKS :=
endif

all: tz_transport

tz_transport: tz_transport.c
	$(MAKE) -C $(PQHID) libpqhid.a
	$(CC) $(CFLAGS) -I$(PQHID) $< $(PQHID)/libpqhid.a $(FRAMEWORKS) -o $@

# Convenience wrappers for the Rust examples.
tz_test:
	cargo run -p pqf-ctaphid --example tz_test --target $(HOST) -- $(ARGS)

tz_cm:
	cargo run -p pqf-ctaphid --example tz_cm --target $(HOST) -- $(ARGS)

clean:
	rm -f tz_transport

.PHONY: all clean tz_test tz_cm
