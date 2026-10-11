# Host-side test harness for the vendored OpenSSL primitives.
#
# Builds and runs the unit tests on the developer's machine (not the
# RP2350), so we can validate the primitives end-to-end against
# known-answer test vectors before they ship in the firmware.
#
# Usage:
#   make test        -- build + run every test_*
#   make test_sha256 -- build + run just SHA-256 tests
#   make clean
#
# Copyright 2026 Cryptsoft Pty Ltd
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# at https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

CC     ?= cc
CFLAGS ?= -O2 -Wall -Wextra -pedantic -std=c11
# openssl-mini no longer reaches outside its own directory -- it uses
# OPENSSL_cleanse from include/openssl/crypto.h -- so ../../src is not
# needed to build the library. It stays on the include path only so a
# test can pull in a firmware header if one is ever useful.
CFLAGS += -I ../include -I ../src -I ../../src

OPENSSL_SRC = ../src/sha256.c ../src/aes_core.c
PQF_SRC     = ../src/pqf_sha256.c \
              ../src/pqf_hmac_sha256.c \
              ../src/pqf_aes.c

# BN host smoke test: links the whole vendored BN tree to confirm
# every translation unit's externals resolve. host_rand_stub.c
# bridges RAND_* (firmware uses the RP2350 TRNG, host uses arc4random)
# and stubs out the EVP_Digest* surface bn_rand.c references for
# DSA paths we never hit.
BN_SRC      = $(wildcard ../src/bn/*.c)
BN_STUB     = host_rand_stub.c
BN_INC      = -I ../src/bn

# P-256 test links the FULL stack: every BN + every EC source + the
# SHA-256/512 + EVP digest layer + the pqf_p256 / pqf_ecdsa_sig
# adapters. host_rand_stub.c supplies RAND_* (TRNG on the firmware).
# Deprecation warnings are silenced -- the OpenSSL 3.x EC_KEY API is
# deprecated-but-internal, exactly the use upstream still supports.
EC_SRC      = $(wildcard ../src/ec/*.c)
# pqf_evp.c's digest table covers SHAKE as well as SHA-2, so every link
# that pulls in pqf_evp.c also needs sha3.c + keccak1600.c.
DIGEST_SRC  = ../src/sha256.c ../src/sha512.c ../src/sha3.c \
              ../src/keccak1600.c ../src/pqf_evp.c
P256_SRC    = $(BN_SRC) $(EC_SRC) $(DIGEST_SRC)
P256_INC    = -I ../src/bn -I ../src/ec
# gnu11 (not c11): the vendored sha512.c uses GNU `asm` rotate
# intrinsics that strict ISO C rejects. The firmware build
# (arm-none-eabi-gcc) defaults to gnu mode, so this matches it.
P256_CFLAGS = -O2 -Wall -Wno-deprecated-declarations -std=gnu11 \
              -I ../include $(P256_INC)

# ML-DSA test links the P-256 stack (the ML_DSA_KEY lifecycle drags in
# the BN/EC allocator surface) plus the ml_dsa core, the SHAKE sources
# and the WPACKET/BUF_MEM helpers its encoders use.
MLDSA_SRC    = $(wildcard ../src/ml_dsa/*.c) ../src/packet.c \
               ../src/buffer.c ../src/pqf_sha256.c
MLDSA_CFLAGS = $(P256_CFLAGS) -I ../src -I ../../src -I ../src/ml_dsa

.PHONY: all test test_sha256 test_hmac_sha256 test_aes test_bn test_p256 \
        test_mldsa clean

all: test_sha256 test_hmac_sha256 test_aes test_bn test_p256 test_mldsa

test: test_sha256 test_hmac_sha256 test_aes test_bn test_p256 test_mldsa

test_sha256: build/test_sha256
	@echo "--- test_sha256 ---"
	@./build/test_sha256

test_hmac_sha256: build/test_hmac_sha256
	@echo "--- test_hmac_sha256 ---"
	@./build/test_hmac_sha256

test_aes: build/test_aes
	@echo "--- test_aes ---"
	@./build/test_aes

build/test_sha256: test_sha256.c $(OPENSSL_SRC) $(PQF_SRC)
	@mkdir -p build
	$(CC) $(CFLAGS) -o $@ test_sha256.c $(OPENSSL_SRC) $(PQF_SRC)

build/test_hmac_sha256: test_hmac_sha256.c $(OPENSSL_SRC) $(PQF_SRC)
	@mkdir -p build
	$(CC) $(CFLAGS) -o $@ test_hmac_sha256.c $(OPENSSL_SRC) $(PQF_SRC)

build/test_aes: test_aes.c $(OPENSSL_SRC) $(PQF_SRC)
	@mkdir -p build
	$(CC) $(CFLAGS) -o $@ test_aes.c $(OPENSSL_SRC) $(PQF_SRC)

test_bn: build/test_bn
	@echo "--- test_bn ---"
	@./build/test_bn

# bn_rand.c references the EVP digest layer for its DSA-nonce helper,
# so the BN link now needs pqf_evp + the SHA sources too. Built with
# the same gnu11 / no-pedantic flags as test_p256 because sha512.c
# uses GNU `asm` rotates that -pedantic -std=c11 rejects (the firmware
# arm-none-eabi-gcc build is gnu mode by default, so this matches it).
build/test_bn: test_bn.c $(BN_STUB) $(BN_SRC) $(DIGEST_SRC)
	@mkdir -p build
	$(CC) $(P256_CFLAGS) -o $@ \
	    test_bn.c $(BN_STUB) $(BN_SRC) $(DIGEST_SRC)

test_p256: build/test_p256
	@echo "--- test_p256 ---"
	@./build/test_p256

build/test_p256: test_p256.c $(BN_STUB) $(P256_SRC)
	@mkdir -p build
	$(CC) $(P256_CFLAGS) -o $@ test_p256.c $(BN_STUB) $(P256_SRC)

test_mldsa: build/test_mldsa
	@echo "--- test_mldsa ---"
	@./build/test_mldsa

build/test_mldsa: test_mldsa.c $(BN_STUB) $(P256_SRC) $(MLDSA_SRC)
	@mkdir -p build
	$(CC) $(MLDSA_CFLAGS) -o $@ \
	    test_mldsa.c $(BN_STUB) $(P256_SRC) $(MLDSA_SRC)

clean:
	rm -rf build
