# Copyright 2026 Cryptsoft Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Host tests for the gadget's network stack -- no board, no pico-sdk build.
#
# Compiles the real net_glue.c and dhcp_server.c against lwIP from the
# pico-sdk checkout, with TinyUSB and the pico-sdk stubbed in
# host_stubs.c. See test_net.c for what this can and cannot settle.
#
#   make            # build and run
#   PICO_SDK_PATH=... make

PICO_SDK_PATH ?= $(HOME)/pico-sdk
LWIP          := $(PICO_SDK_PATH)/lib/lwip

CC      ?= cc
CFLAGS  := -std=c11 -O1 -g -Wall -Wextra -Wno-unused-parameter -Wno-macro-redefined \
           -I. -I../src -I.. \
           -I$(LWIP)/src/include -I$(LWIP)/src/include/compat/posix \
           -DPQF_GADGET_CONSOLE=0
LDFLAGS :=

LWIP_SRC := \
  $(LWIP)/src/core/init.c $(LWIP)/src/core/def.c $(LWIP)/src/core/inet_chksum.c \
  $(LWIP)/src/core/ip.c $(LWIP)/src/core/mem.c $(LWIP)/src/core/memp.c \
  $(LWIP)/src/core/netif.c $(LWIP)/src/core/pbuf.c $(LWIP)/src/core/raw.c \
  $(LWIP)/src/core/stats.c $(LWIP)/src/core/sys.c $(LWIP)/src/core/tcp.c \
  $(LWIP)/src/core/tcp_in.c $(LWIP)/src/core/tcp_out.c $(LWIP)/src/core/timeouts.c \
  $(LWIP)/src/core/udp.c \
  $(LWIP)/src/core/ipv4/acd.c $(LWIP)/src/core/ipv4/etharp.c \
  $(LWIP)/src/core/ipv4/icmp.c $(LWIP)/src/core/ipv4/ip4.c \
  $(LWIP)/src/core/ipv4/ip4_addr.c $(LWIP)/src/core/ipv4/ip4_frag.c \
  $(LWIP)/src/core/ipv4/igmp.c \
  $(LWIP)/src/netif/ethernet.c \
  $(LWIP)/src/api/err.c \
  $(LWIP)/src/apps/mdns/mdns.c \
  $(LWIP)/src/apps/mdns/mdns_out.c \
  $(LWIP)/src/apps/mdns/mdns_domain.c

GADGET_SRC := ../src/net_glue.c ../src/dhcp_server.c ../src/http_status.c

SRC := test_net.c host_stubs.c $(GADGET_SRC) $(LWIP_SRC)

all: build/test_net
	./build/test_net

build/test_net: $(SRC) host_stubs.h lwipopts.h
	@mkdir -p build
	$(CC) $(CFLAGS) -include host_stubs.h -o $@ $(SRC) $(LDFLAGS)

clean:
	rm -rf build

.PHONY: all clean
