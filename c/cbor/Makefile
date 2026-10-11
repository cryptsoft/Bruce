# Copyright 2026 Cryptsoft Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# pqcbor -- minimal CBOR decoder (C).
#
# Builds:
#   libpqcbor.a   -- static archive of pqcbor.o.
#   smoke         -- tiny test program; runs as part of `make test`.
#
# No external deps. ANSI C, builds clean under -Wall -Wextra -pedantic.

CC      ?= cc
AR      ?= ar
CFLAGS  ?= -O2 -Wall -Wextra -pedantic -std=c11
CFLAGS  += -fPIC

LIB     = libpqcbor.a
OBJS    = pqcbor.o

.PHONY: all test clean

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $^

pqcbor.o: pqcbor.c pqcbor.h
	$(CC) $(CFLAGS) -c pqcbor.c -o pqcbor.o

# Smoke test -- decodes a hand-built CBOR map and dumps it.
smoke: smoke.c $(LIB)
	$(CC) $(CFLAGS) smoke.c $(LIB) -o smoke

test: smoke
	./smoke

clean:
	rm -f $(OBJS) $(LIB) smoke
