# Copyright 2026 Cryptsoft Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# pqhid -- CTAP-over-USB-HID transport (C).
#
# Builds:
#   libpqhid.a   -- static archive: platform-independent core (pqhid.o)
#                  plus exactly one per-OS backend, selected from
#                  `uname -s` (override with OS_BACKEND=linux|macos|windows):
#
#                    Linux    pqhid_linux.o    (hidraw + poll)
#                    Darwin   pqhid_macos.o    (IOKit; consumers must link
#                                              -framework IOKit
#                                              -framework CoreFoundation)
#                    MINGW*   pqhid_windows.o  (SetupAPI + hid.dll + bcrypt)
#
#   smoke        -- tiny test program; runs as part of `make test`.
#                  Needs no device.
#
# No external deps beyond the OS itself. Builds clean under
# -Wall -Wextra -pedantic.

CC      ?= cc
AR      ?= ar
RANLIB  ?= ranlib
CFLAGS  ?= -O2 -Wall -Wextra -pedantic -std=c11
CFLAGS  += -fPIC

UNAME_S := $(shell uname -s)

# ---- Backend selection ----
ifndef OS_BACKEND
  ifeq ($(UNAME_S),Linux)
    OS_BACKEND = linux
  else ifeq ($(UNAME_S),Darwin)
    OS_BACKEND = macos
  else ifneq (,$(findstring MINGW,$(UNAME_S)))
    OS_BACKEND = windows
  else ifneq (,$(findstring MSYS,$(UNAME_S)))
    OS_BACKEND = windows
  else
    $(error unsupported platform '$(UNAME_S)' -- set OS_BACKEND=linux|macos|windows)
  endif
endif

ifeq ($(OS_BACKEND),linux)
  OS_OBJ   = pqhid_linux.o
  OS_LIBS  =
else ifeq ($(OS_BACKEND),macos)
  OS_OBJ   = pqhid_macos.o
  OS_LIBS  = -framework IOKit -framework CoreFoundation
else ifeq ($(OS_BACKEND),windows)
  OS_OBJ   = pqhid_windows.o
  OS_LIBS  = -lhid -lsetupapi -lbcrypt
else
  $(error OS_BACKEND must be linux, macos or windows)
endif

LIB     = libpqhid.a
OBJS    = pqhid.o $(OS_OBJ)

.PHONY: all test clean

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $^
	$(RANLIB) $@

pqhid.o: pqhid.c pqhid.h pqhid_os.h
	$(CC) $(CFLAGS) -c pqhid.c -o $@

pqhid_linux.o: pqhid_linux.c pqhid.h pqhid_os.h
	$(CC) $(CFLAGS) -c pqhid_linux.c -o $@

pqhid_macos.o: pqhid_macos.c pqhid.h pqhid_os.h
	$(CC) $(CFLAGS) -c pqhid_macos.c -o $@

pqhid_windows.o: pqhid_windows.c pqhid.h pqhid_os.h
	$(CC) $(CFLAGS) -c pqhid_windows.c -o $@

# Smoke test -- verifies the library builds, links, reports its version,
# and rejects NULL arguments at every entry point.
smoke: smoke.c $(LIB)
	$(CC) $(CFLAGS) smoke.c $(LIB) $(OS_LIBS) -o smoke

test: smoke
	./smoke

# reboot -- CLI to reboot a token into BOOTSEL (or warm) via the vendor
# command CTAPHID_CMD_REBOOT. Needs a device attached; touch-gated on
# builds that enforce user presence. See reboot.c.
reboot: reboot.c $(LIB)
	$(CC) $(CFLAGS) reboot.c $(LIB) $(OS_LIBS) -o reboot

# rng: pull bytes from CMD_RNG and time them -- says whether the QRNG
# (I2C-bound, ~330 ms/KiB) or the on-die TRNG (ms) served the request.
rng: rng.c $(LIB)
	$(CC) $(CFLAGS) rng.c $(LIB) $(OS_LIBS) -o rng

clean:
	rm -f pqhid.o pqhid_linux.o pqhid_macos.o pqhid_windows.o $(LIB) smoke smoke.exe reboot reboot.exe rng rng.exe
