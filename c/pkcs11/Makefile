# Copyright 2026 Cryptsoft Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# pqf-pkcs11 -- PKCS#11 module exposing the Bruce token as an RNG.
#
# Builds pqf-pkcs11.dylib (macOS) / pqf-pkcs11.so (Linux) from the
# single-file module plus the vendored pqhid transport in ../hid.
#
#   make          -- build the shared module
#   make test     -- run the no-device smoke test (dlopen + function
#                   list sanity)
#   make clean
#
# Live check (token attached, firmware with CTAPHID_CMD_RNG):
#   pkcs11-tool --module ./pqf-pkcs11.$(SHLIB_EXT) --generate-random 32

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -pedantic -std=c90
CFLAGS  += -fPIC -I. -I../hid

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
  SHLIB_EXT  = dylib
  SHLIB_FLAG = -dynamiclib
  OS_LIBS    = -framework IOKit -framework CoreFoundation
else
  SHLIB_EXT  = so
  SHLIB_FLAG = -shared
  OS_LIBS    =
endif

MODULE = pqf-pkcs11.$(SHLIB_EXT)
PQHID  = ../hid/libpqhid.a

.PHONY: all test clean

all: $(MODULE)

$(PQHID):
	$(MAKE) -C ../hid

pqf_pkcs11.o: pqf_pkcs11.c cryptoki.h oasis/pkcs11.h oasis/pkcs11t.h \
  oasis/pkcs11f.h ../hid/pqhid.h
	$(CC) $(CFLAGS) -c pqf_pkcs11.c -o $@

$(MODULE): pqf_pkcs11.o $(PQHID)
	$(CC) $(SHLIB_FLAG) -o $@ pqf_pkcs11.o $(PQHID) $(OS_LIBS)

# Smoke test -- dlopens the module and walks the Cryptoki entry points
# that work without a device. Needs no token attached.
smoke: smoke.c $(MODULE)
	$(CC) $(CFLAGS) smoke.c -o smoke

test: smoke
	./smoke ./$(MODULE)

# Proof demo -- dlopens the module and shows the entropy is the token's
# (identity / liveness / quality; `-i` adds the unplug/replug test).
# Needs a token attached.
proof: proof.c $(MODULE)
	$(CC) $(CFLAGS) proof.c -lm -o proof

clean:
	rm -f pqf_pkcs11.o $(MODULE) smoke proof
