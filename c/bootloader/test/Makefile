# Host-side tests for the DFU bootloader's signed-image verifier.
#
# Mirrors c/firmware/test/Makefile: compiles the EXACT verification TU
# the bootloader links (c/common/pqf_image_verify.c) plus the crypto
# subset on the host, and drives every accept/reject path. `make
# interop` additionally round-trips a tools/pqf_sign.py-signed file
# through the C verifier (needs python3 + the cryptography package).
#
# Usage:  make test      unit tests (no external deps)
#         make interop   python signer -> C verifier round trip
#         make clean
#
# SPDX-License-Identifier: Apache-2.0

CC     ?= cc
OM      = ../../firmware/openssl-mini
CFLAGS  = -O2 -Wall -Wno-deprecated-declarations -std=gnu11 \
          -I ../../common -I $(OM)/include \
          -I $(OM)/src -I $(OM)/src/bn -I $(OM)/src/ec

OM_SRC  = $(wildcard $(OM)/src/bn/*.c) $(wildcard $(OM)/src/ec/*.c) \
          $(OM)/src/sha256.c $(OM)/src/sha512.c $(OM)/src/sha3.c \
          $(OM)/src/keccak1600.c $(OM)/src/pqf_sha256.c $(OM)/src/pqf_evp.c

SRC     = ../../common/pqf_image_verify.c $(OM_SRC) \
          $(OM)/test/host_rand_stub.c

.PHONY: test interop clean

test: build/test_image_verify
	./build/test_image_verify

build/test_image_verify: test_image_verify.c $(SRC) ../../common/pqf_image.h
	@mkdir -p build
	$(CC) $(CFLAGS) -o $@ test_image_verify.c $(SRC)

# Python signer -> C verifier round trip, positive AND negative: a
# fresh throwaway key signs a pretend image; the C verifier must
# accept it, and must reject a one-byte-corrupted copy.
interop: build/test_image_verify
	@mkdir -p build
	python3 -c "import secrets; open('build/fake_fw.bin','wb').write(secrets.token_bytes(50000))"
	python3 ../../../tools/pqf_sign.py keygen --key build/interop-key.pem --force >/dev/null
	python3 ../../../tools/pqf_sign.py sign --key build/interop-key.pem \
	    --in build/fake_fw.bin --out build/fake_fw.dfu --fw-version 7 >/dev/null
	@X=$$(python3 -c "from cryptography.hazmat.primitives import serialization; \
	    from cryptography.hazmat.primitives.asymmetric import ec; \
	    k=serialization.load_pem_private_key(open('build/interop-key.pem','rb').read(),None); \
	    n=k.public_key().public_numbers(); print(format(n.x,'064x'))"); \
	Y=$$(python3 -c "from cryptography.hazmat.primitives import serialization; \
	    from cryptography.hazmat.primitives.asymmetric import ec; \
	    k=serialization.load_pem_private_key(open('build/interop-key.pem','rb').read(),None); \
	    n=k.public_key().public_numbers(); print(format(n.y,'064x'))"); \
	./build/test_image_verify build/fake_fw.dfu $$X $$Y || exit 1; \
	python3 -c "b=bytearray(open('build/fake_fw.dfu','rb').read()); b[5000]^=1; \
	    open('build/fake_fw_bad.dfu','wb').write(bytes(b))"; \
	if ./build/test_image_verify build/fake_fw_bad.dfu $$X $$Y; then \
	    echo "FAIL: corrupted image was accepted"; exit 1; \
	else echo "ok: corrupted image rejected"; fi

clean:
	rm -rf build
