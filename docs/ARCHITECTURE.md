# Architecture

How the firmware is put together and why: the module layout of the Rust firmware, the two-core signing design, the shared-SRAM contract, the heap, the flash schema and its history, and a one-to-one map onto the C port at the end. It is for someone who is about to read or change the code, and assumes the vocabulary of [PROTOCOL.md](PROTOCOL.md). Building is covered by [BUILD.md](BUILD.md) and [GETTING-STARTED.md](GETTING-STARTED.md); what has been verified on silicon by [TESTING.md](TESTING.md).

Contents:

- [Source layout](#source-layout)
- [Layered request flow](#layered-request-flow)
- [Why two cores](#why-two-cores)
- [Shared-SRAM synchronisation](#shared-sram-synchronisation)
- [Heap](#heap)
- [Flash schema evolution](#flash-schema-evolution)
- [Hybrid signing contract](#hybrid-signing-contract)
- [Cargo-feature variant selection](#cargo-feature-variant-selection)
- [Why no `defmt`, no `probe-rs`, no panic-handler beyond `panic-halt`?](#why-no-defmt-no-probe-rs-no-panic-handler-beyond-panic-halt)
- [The C port (`c/firmware/`)](#the-c-port-cfirmware)

`bruce` is bare-metal Rust running on the RP2350's two Cortex-M33 cores. There is no operating system, no scheduler, no threads -- just a polling main loop on core 0 plus a dedicated signing worker on core 1, synchronised through a shared SRAM data structure. (The optional `single_core` build, [BUILD.md Axis 6](BUILD.md#axis-6-optional-single-core-single_core), leaves core 1 asleep: the signer runs inline on core 0 and a `TIMER0` alarm interrupt carries the `KEEPALIVE` cadence that the wait loop below otherwise pumps.) This document explains why the codebase looks the way it does.

## Source layout

The modules on the request path, with their line counts as of 2026-09-22:

| Module                                | LOC   | Role                                                                                                                                                                                |
| ---                                   | ---   | ---                                                                                                                                                                                 |
| [`crates/firmware/src/main.rs`](../crates/firmware/src/main.rs)             | 1242  | Hardware bring-up; clocks, USB, GPIO, RGB LED, TRNG; spawns core 1; runs the USB-poll + CTAP HID main loop                                                                          |
| [`crates/firmware/src/fido_hid.rs`](../crates/firmware/src/fido_hid.rs)     | 366   | `usb-device` HID class for the FIDO usage page (`0xF1D0`). 64-byte interrupt-IN / interrupt-OUT endpoints, hand-rolled report descriptor (the standard HID macros don't fit FIDO)   |
| [`crates/firmware/src/ctaphid.rs`](../crates/firmware/src/ctaphid.rs)       | 604   | CTAP HID transport: channel ID allocation, multi-frame INIT/PING/WINK/CBOR/CANCEL/KEEPALIVE framing                                                                                  |
| [`crates/firmware/src/ctap2.rs`](../crates/firmware/src/ctap2.rs)           | 3045  | The CTAP2 layer itself: dispatch, `getInfo` shape, `MakeCredential`, `GetAssertion`, `Reset`, `Selection`, the `CredStore` over the flash slots, extension parsing & emission        |
| [`crates/firmware/src/core1_signer.rs`](../crates/firmware/src/core1_signer.rs) | 36  | The firmware-side anchor of the core-1 signing worker: owns the `CORE1_SIGNER` mailbox static and core 1's stack. The worker itself -- shared SRAM contract, `AtomicU8` state machine, hybrid signing pipeline -- lives in `crates/signer-core` (`pqf-signer-core`) so the same code can be cross-compiled for the mixed-ISA build ([RISCV.md](RISCV.md)) |
| [`crates/firmware/src/keepalive_timer.rs`](../crates/firmware/src/keepalive_timer.rs) | 195 | `single_core` only: `TIMER0` alarm 0 fires every 25 ms during a CTAP2 dispatch; the handler sends one `KEEPALIVE` on the in-flight channel and services USB. Armed/disarmed around `handle_cbor`, a guard keeps it off the stack while the `host` closure has it |
| [`crates/firmware/src/credential_id.rs`](../crates/firmware/src/credential_id.rs) | 536 | 161-byte encrypted credentialID encode / decode (carries credProtect) / `cred_random` and `largeBlobKey` derivation under the domain labels of [HMAC-DOMAINS.md](HMAC-DOMAINS.md)  |
| [`crates/firmware/src/client_pin.rs`](../crates/firmware/src/client_pin.rs) | 1160  | CTAP2 `authenticatorClientPin` -- both PIN protocol v1 and v2, ECDH key agreement, `SharedSecret` enum, AES-CBC / HMAC helpers                                                       |
| [`crates/firmware/src/flash_store.rs`](../crates/firmware/src/flash_store.rs) | 739 | QSPI flash persistence in the top three 4 KiB sectors (`0x103FF000` PIN/config + resident slots, `0x103FE000` large-blob array, `0x103FD000` master keys), plus any overflow resident-credential sectors below them (`PQF_RESIDENT_EXTRA_SECTORS`, none by default), via the RP2350 boot ROM flash routines |
| [`crates/firmware/src/mldsa_alg.rs`](../crates/firmware/src/mldsa_alg.rs)   | 48    | `cfg`-aliased ML-DSA-44 / 65 / 87 type + constant selection per cargo feature                                                                                                       |
| [`crates/firmware/src/trng.rs`](../crates/firmware/src/trng.rs)             | 199   | Minimal driver for the RP2350 ring-oscillator TRNG; provides `RngCore + CryptoRng`                                                                                                  |
| [`crates/firmware/src/qrng.rs`](../crates/firmware/src/qrng.rs)             | 589   | external quantum RNG on the QW/ST connector (I2C0): probe, packet framing + health, SHA-256 conditioning (64 -> 32), failure policy; `hw` = bounded PAC-level I2C transport and stuck-bus recovery |
| [`crates/firmware/src/entropy.rs`](../crates/firmware/src/entropy.rs)       | 144   | The entropy picker `main.rs` hands to CTAP: QRNG first when present, TRNG completes the rest; `RngCore + CryptoRng`                                                                 |
| **Total**                              | **8903** |                                                                                                                                                                                  |

Not in the table, because they are documented elsewhere or are straightforward: `credential_management.rs`, `large_blobs.rs`, `authenticator_config.rs` (the CTAP 2.1 management commands, [PROTOCOL.md](PROTOCOL.md)); `u2f.rs` (feature-gated, unreachable by default); `board/` (the per-board profiles, [HARDWARE.md](HARDWARE.md)); `core1_launch.rs` and `arch.rs` ([RISCV.md](RISCV.md)); `dfu_runtime.rs` ([DFU.md](DFU.md)); `gdbstub.rs` ([GDB_DEBUG.md](GDB_DEBUG.md)); `ramfunc.rs` (the routines that must run from RAM while XIP is suspended).

The remaining linker / build scaffolding (`crates/firmware/memory.x`, `.cargo/config.toml`, `rust-toolchain.toml`) is documented in [BUILD.md](BUILD.md).

## Layered request flow

A single `authenticatorMakeCredential` from Chrome takes this path:

```
                +---------------- host (Chrome / Firefox / pqf-ctaphid) -------------+
                |   navigator.credentials.create({publicKey: {...}})                 |
                +----------------------------+---------------------------------------+
                                             |  USB control + interrupt IN/OUT
                                             |  64-byte HID reports on the FIDO
                                             |  usage page (0xF1D0)
                                             v
+--- Core 0 main loop ----------------------------------------------------------------+
|                                                                                    |
|   crates/firmware/src/main.rs                                                      |
|     usb_dev.poll(&mut [&mut fido])  <-------------------------------------+        |
|            |                                                              |        |
|            v                                                              |        |
|   crates/firmware/src/fido_hid.rs                                         |        |
|     FidoHidClass::recv_frame()  --> raw [u8; 64] interrupt-OUT frame     |        |
|            |                                                              |        |
|            v                                                              |        |
|   crates/firmware/src/ctaphid.rs                                          |        |
|     CtapHid::handle_frame() reassembles INIT / PING / WINK / CBOR /       |        |
|     CANCEL / KEEPALIVE channels, returns either an immediate Response     |        |
|     (e.g. PING echo) or a complete CborMessage when the CTAP2 envelope    |        |
|     finishes                                                              |        |
|            |                                                              |        |
|            v                                                              |        |
|   ctaphid::FrameOutcome::CborMessage { cid, payload }                     |        |
|            |                                                              |        |
|            |   <--- before the next phase main.rs pushes ONE keepalive    |        |
|            |       frame on the wire so the host's CTAP HID watchdog     |        |
|            |       knows we're still alive while ctap2:: digests the     |        |
|            |       request                                                |        |
|            v                                                              |        |
|   crates/firmware/src/ctap2.rs                                            |        |
|     handle_cbor(payload, trng, pin_session, cred_store, &mut tick)        |        |
|       +-> emit_make_credential(...)                                       |        |
|             |- parse CBOR map (rp, user, pubKeyCredParams, options,       |        |
|             |  extensions: hmac-secret / credProtect / credBlob, pin)    |        |
|             |- verify pinUvAuthParam (v1: 16 B truncated HMAC, v2:        |        |
|             |  full 32 B) -- only if a PIN is set on the device           |        |
|             |- generate ECDSA-P256 scalar + ML-DSA seed                   |        |
|             |- encrypt keys + rp_id_hash into the 161-byte credentialID   |        |
|             |  (crates/firmware/src/credential_id.rs)                     |        |
|             |- insert into flash slot for rk-discoverability              |        |
|             |- build authData with COSE_Key + extensions output           |        |
|             |- build msg = authData || clientDataHash                     |        |
|             +- opensk_hybrid_sign(ecdsa_scalar, ml_dsa_seed, msg, tick)   |        |
|                              |                                            |        |
|                              v                                            |        |
|   crates/firmware/src/core1_signer.rs::submit()                           |        |
|     stash inputs into CORE1_SIGNER shared SRAM region;                    |        |
|     state.store(REQUESTED, Release); sev();                               |        |
|                              |                                            |        |
|                              v                                            |        |
|     while !CORE1_SIGNER.is_done() { tick(); wfe(); }                      |        |
|              |   tick() = 3x KEEPALIVE frame + usb_dev.poll()             |        |
|              |   wfe() parks until USB IRQ or core-1's sev()              |        |
|              v                                                            |        |
|     CORE1_SIGNER.take_result(&mut out)                                    |        |
|              |                                                            |        |
|              v                                                            |        |
|   ctap2:: assembles the attestation response, returns AllocVec<u8>        |        |
|   to ctaphid::, which fragments it into 64-byte INIT + CONT frames        |        |
|   and ships them back through fido_hid + usb-device                       |        |
+------------------------------------------------------------------------------------+
                                             ^
                                             |  USB interrupt-IN frames
                                             |
                                             |
+--- Core 1 signing worker (idle until poked) ----------------------------------------+
|                                                                                     |
|   crates/firmware/src/core1_signer.rs::worker()                                     |
|     loop {                                                                          |
|         while state.load(Acquire) != REQUESTED { wfe(); }                           |
|         state.store(RUNNING, Release);                                              |
|                                                                                     |
|         // 1) ECDSA-P256 deterministic sign of SHA-256(LABEL || msg)                |
|         let prehash = sha256(HYBRID_LABEL || msg);                                  |
|         let ecdsa_der = sign_prehash(scalar, prehash).to_der();                     |
|                                                                                     |
|         // 2) ML-DSA-44/65/87 keygen from seed (~20 ms keygen + ~1 s sign)          |
|         let (_pk, sk) = MLDSA::keygen_from_seed(seed);                              |
|         let tr = sk.tr();                                                           |
|                                                                                     |
|         // 3) mu = SHAKE-256(tr || 0x00 || 0x00 || LABEL || msg || ecdsa_der)       |
|         let mu = MuBuilder::do_init(&tr, Some(b""))                                 |
|              .do_update(HYBRID_LABEL).do_update(msg).do_update(ecdsa_der)           |
|              .do_final();                                                           |
|                                                                                     |
|         // 4) rnd = 0^32 (FIPS 204 deterministic variant; see PROTOCOL.md)         |
|         let rnd = [0u8; 32];                                                        |
|                                                                                     |
|         // 5) sign_mu_deterministic_out(sk, mu, rnd, &mut mldsa_sig)                |
|         MLDSA::sign_mu_deterministic_out(&sk, &mu, rnd, &mut mldsa_sig);            |
|                                                                                     |
|         // 6) publish: out = ecdsa_der || mldsa_sig (no length prefix)              |
|         state.store(DONE, Release);                                                 |
|         sev();                                                                      |
|     }                                                                               |
+-------------------------------------------------------------------------------------+
```

The exact `LABEL`, mu construction, and wire format are byte-identical to OpenSK's PQC fork `OpenSK/libraries/crypto/src/hybrid.rs::sign_rfc6979` -- see [PROTOCOL.md](PROTOCOL.md) for the bytes-on-the-wire.

## Why two cores

Earlier builds did all the ML-DSA work on core 0. That stopped at the first contact with Chrome:

- ML-DSA-65 keygen + sign on the low-memory bouncycastle crate takes roughly **1.0 - 1.3 s on a Cortex-M33 at 125 MHz**.
- Chrome's CTAP HID watchdog wants activity at a **~100 ms cadence**. If nothing arrives for ~2 s the JS-side WebAuthn call rejects with a generic `NotAllowedError`. The user sees *"the operation timed out"*.
- OpenSK gets around this by running on the Tock OS kernel -- a 100 ms timer interrupts userland and lets it emit a `KEEPALIVE` from the timer handler. Our build is bare-metal; nothing pre-empts the rejection-sampling loop inside ML-DSA signing.
- Patching the bouncycastle crate to yield periodically would mean forking and maintaining it, which the project ruled out (the vendored crates under `crates/bc-rust-mini` are an unmodified snapshot, [BUILD.md](BUILD.md#vendored-dependencies)).

So we offload the entire hybrid sign -- ECDSA prehash + sign, plus ML-DSA keygen + sign -- to **core 1**, and let core 0 pump KEEPALIVE frames at ~50 ms cadence between USB polls while core 1 grinds. The 3x signing-time penalty of the low-memory crate becomes invisible to the host because the transport never goes silent.

## Shared-SRAM synchronisation

`CORE1_SIGNER` is a single `static` in `.bss` (the type lives in `crates/signer-core/src/signer.rs`, the static in `crates/firmware/src/core1_signer.rs`):

```rust
#[repr(C, align(32))]
pub struct Core1Signer {
    state: AtomicU8,
    pub park_request: AtomicBool,   // flash-park handshake: core 0 asks core 1 to
    pub park_ack: AtomicBool,       // spin in RAM before an erase/program (audit M1)
    msg_len: AtomicU16,
    ecdsa_der_len: AtomicU16,
    ecdsa_scalar: UnsafeCell<[u8; 32]>,
    mldsa_seed:   UnsafeCell<[u8; 32]>,
    msg:          UnsafeCell<[u8; MAX_MSG_LEN]>,
    ecdsa_der:    UnsafeCell<[u8; 80]>,
    mldsa_sig:    UnsafeCell<[u8; MLDSA_SIG_LEN]>,
}

pub static CORE1_SIGNER: Core1Signer = Core1Signer::new();
```

`UnsafeCell` makes the byte buffers interior-mutable; `AtomicU8` orders the access:

```
       core 0                                         core 1

   submit() :
     wait state == IDLE
     write inputs
     state.store(REQUESTED, Release)                 idle in wfe()
     sev()                                            wakes
                                                     - state.load(Acquire) -> REQUESTED, ok
                                                     state.store(RUNNING, Release)
                                                     read inputs
                                                     do crypto
                                                     write outputs
     wfe() / tick() / wfe() / tick() / ...             state.store(DONE, Release)
                                                     sev()
       - state.load(Acquire) -> DONE yes
       take_result() :
         read outputs
         state.store(IDLE, Release)
         sev()                                        cycle repeats
```

The Acquire / Release pairing makes the byte-buffer writes happen-before the consumer's reads. RP2350 SRAM is unified and visible to both cores, but each core has its own L1-style cache; the rp235x-hal sets `ACTLR.EXTEXCLALL` in `Multicore::new` to make ARM's atomic instructions actually go through to SRAM rather than each core's local cache. Without that, atomics would only be visible within the same core.

`wfe()` (wait-for-event) parks the core until any event fires -- including USB SOF interrupts (every 1 ms), USB completions, and the cross-core `sev()`. The waiting loop is cheap in both power and time:

```rust
while !signer.is_done() {
    tick();             // 3x KEEPALIVE frame + usb_dev.poll()
    cortex_m::asm::wfe();
}
```

`tick()` is also the keepalive pump that keeps the host's watchdog happy. It's idempotent: USB SOF wakes us, we send a keepalive, we wfe back. Even if core 1 finishes between two ticks the next tick's `is_done()` check picks it up.

## Heap

`embedded-alloc::LlffHeap` (256 KiB), initialised once on core 0 in `main()`:

```rust
const HEAP_SIZE: usize = 256 * 1024;

#[global_allocator]
static HEAP: Heap = Heap::empty();

unsafe { HEAP.init(HEAP_MEM.as_ptr() as usize, HEAP_SIZE); }
```

Core 1 uses the same global allocator. LLFF's free-list is protected by a `critical_section`; with the `rp235x-hal/critical-section-impl` feature, `critical_section` uses an RP2350 hardware spinlock that's safe across both cores. So when core 0 and core 1 happen to allocate at the same time, the second one spins briefly. In practice this almost never happens -- core 0's `tick()` doesn't allocate, and core 1's allocations cluster around the ML-DSA polynomial / SHAKE state.

256 KiB is generous -- even ML-DSA-87 (the heaviest variant) keeps the high-water mark around 90 KiB on the low-memory crate.

## Flash schema evolution

The credential store lives in the **last 4 KiB sector of the QSPI flash** (offset `0x103FF000` on a 4 MiB part). Since schema v11 it is one of three reserved sectors: the large-blob array has the sector below it (`0x103FE000`) and the two master keys the one below that (`0x103FD000`, `KEY_OFFSET`), each with its own magic and version. The on-disk layout is bumped via a version field in the header so each schema change auto-invalidates the previous sector on first boot.

| Version | Introduced              | Header   | Slot size | Slots / sector | What changed                                                                                          |
| ---     | ---                     | ---      | ---       | ---            | ---                                                                                                   |
| v3      | Initial commit          | 40 B     | 140 B     | 28             | PIN state + credential slots (random 32-byte ID + keys + counter + alg)                              |
| v4      | Phase 1                 | 40 B     | 208 B     | 19             | + per-credential `user_id_len` (1) + 3-pad + `user_id` [u8; 64]                                       |
| v5      | Phase 2                 | 104 B    | 208 B     | 19             | Header gains `key_handle_aes_key` + `key_handle_hmac_key` (32 B each); slot replaces keys with `credential_id: [u8; 241]` |
| v6      | Phase 2 patch (compact) | 104 B    | 256 B     | 15             | `credential_id` shrinks 241 -> 145 B; slot remains 256 B with adjusted padding                          |
| v7      | Phase 4                 | 104 B    | 292 B     | 13             | Slot gains `cred_protect: u8`, `cred_blob_len: u8`, 2-byte pad, `cred_blob: [u8; 32]`                  |
| v8      | Phase 8 (CredMgmt)      | 104 B    | 432 B     | 9              | Slot gains `user_name` + `user_display_name` ([u8; 64] each + len bytes) + `creation_order: u32`        |
| v9      | Phase 9 (AuthConfig)    | 240 B    | 432 B     | 8              | Header grows for `always_uv`, `enterprise_attestation`, `min_pin_length` + a 4-entry RP-id allowlist     |
| v10     | credProtect-in-ID       | 240 B    | 448 B     | 8              | `credential_id` grows 145 -> 161 B (plaintext carries the credProtect policy byte at `[96]`)             |
| v11     | Audit fixes H1 + F4     | 240 B    | 580 B     | 6              | Master keys move out of this sector into their own `KEY_OFFSET` sector, so a torn routine write can never lose them; the slot gains a per-credential UTF-8 `rp_id` (up to 128 B) + `rp_id_len` so `enumerateRPs` can return the real RP id |
| v12     | Audit fix X13           | 240 B    | 580 B     | 6              | The reserved header byte at offset 108 becomes the persistent `force_pin_change` flag (getInfo `0x0C forcePINChange`); the bump regenerates the main sector once so an erased `0xFF` never reads as "force change on". The key sector is untouched, so non-resident credentials still decrypt across it |

The audit labels are those of [docs/notes/audit/AUDIT_FINDINGS.md](notes/audit/AUDIT_FINDINGS.md). The header contains (v12 layout, 240 B):

```
off 0   : SECTOR_MAGIC ("FIDO" little-endian)
off 4   : SECTOR_VERSION (currently 12)
off 8   : pin_hash[16]
off 24  : pin_set (1 B) | retries_left (1 B) | 2-byte pad
off 28  : 12 B reserved
off 40  : 64 B reserved -- v5..v10 held key_handle_aes_key[32] + key_handle_hmac_key[32] here;
          v11 moved them to the KEY_OFFSET sector
off 104 : always_uv (1) | enterprise_attestation (1) | min_pin_length (1) | min_pin_length_rpid_count (1)   (v9+)
off 108 : force_pin_change (1) (v12) | 3 B reserved
off 112 : min_pin_length_rpid_hashes[4][32] (v9+)
off 240 : credential slots (580 B each, 6 of them; the size is pinned by a static assert)
```

### Overflow resident-credential sectors

A build with `PQF_RESIDENT_EXTRA_SECTORS=N` ([BUILD.md](BUILD.md#axis-7-optional-discoverable-credential-capacity)) adds `N` sectors directly below the key sector -- overflow sector `k` at `KEY_OFFSET - (k + 1) x 4 KiB`, i.e. `0x103FC000`, `0x103FB000`, ... -- each holding 7 more slots in the same 580-byte `StoredCredential` layout. The three sectors above are not changed by the option: with `N = 0` (the default) the flash is exactly the layout described here, and a store written by either build is read identically by the other. Each overflow sector has its own 16-byte header:

```
off 0  : "RKOV" magic (0x524B4F56)
off 4  : SECTOR_VERSION (12) -- the slot layout version, shared with the main sector
off 8  : this sector's index k
off 12 : key tag = first 4 bytes of HMAC(key_handle_hmac_key, "pqf-rk-overflow"), little-endian
off 16 : credential slots (580 B each, 7 of them)
```

`CredStore` keeps all `6 + 7N` slots in one heap array (indices `0..6` the main sector's, then 7 per overflow sector) and rewrites only the sector holding a changed slot. An overflow sector is written with every slot byte first and the 16 header bytes last (the whole sector is programmed with the header left erased, then page 0 again with the header), so a torn overflow write reads back as that sector empty and nothing else changed. A sector whose header is absent, of another version, from another index or tagged under other master keys reads as empty and is not written until a credential lands in it -- which is what enlarging `N` over an existing token looks like, and what keeps a sector left behind across an `authenticatorReset` by a build that did not know about it from resurrecting credentials that no longer decrypt. `wipe_all` (Reset) erases every overflow sector.

The C port mirrors this: its resident store keeps its 8-byte-header primary sector (7 slots) and adds overflow sectors below its own key sector (`PICO_FLASH_SIZE_BYTES - (5 + k) x 4 KiB`) with the same 16-byte header shape and 7 slots of 564 B each (`c/firmware/src/resident_store.c`).

`flash_store::read_sector` checks magic + version; mismatch -> returns `None`. `CredStore::load` in `ctap2.rs` then falls through to a cold-boot path that writes a fresh empty sector. The master keys, in their own sector since v11, are **regenerated from TRNG** only when that sector is itself missing or invalid -- which is what happens on the very first boot of a brand-new device -- or on `authenticatorReset`.

`authenticatorReset` (the `reset` example) calls `CredStore::wipe_all(trng)` which **rotates** the master keys (not just zeroes the slots) -- any credentialID cached on a relying party becomes un-decryptable after reset.

**A lost main sector never removes the PIN.** Because the keys survive a torn or corrupt main sector and the PIN does not, a token that had a PIN would otherwise boot PIN-less with every old credential id still decrypting, and anyone holding it could set a PIN of their own. So the first setPIN also programs one word in the key sector's second page -- program-only, no erase, nothing in the keys' page touched -- and `CredStore::load` boots a token whose key sector has that word set but whose main sector holds no PIN as **PIN-blocked** (PIN set, 0 retries): no PIN can be set or used until `authenticatorReset`, which erases the key sector, rotates the keys and so retires every old credential id. A PIN set by a build without the word is armed on the first boot. The main sector itself is written slots first, then its header page with the magic left erased, then the magic alone, so a write cut short anywhere before the magic is complete reads as no main sector at all -- never as a valid header over erased fields (an erased retry counter used to load as the full count). The C port does the same with its own key sector (`arm_pin` in `c/firmware/src/flash_store.c`); its store page is CRC-checked, so a torn commit there already read as no store. Host tests: `crates/firmware-hosttest/tests/pin_armed.rs` and `c/firmware/test/test_flash_store.c` cut the power at every byte of the writes involved. On silicon (the Rust image on the Feitian RP2350, 2026-10-11) the armed word, the PIN-blocked boot after a lost main sector and the reset that clears it were each reproduced; see [TESTING.md](TESTING.md#2026-10-11-a-lost-pin-blocks-and-the-release-reviews-other-findings).

Flash writes go through the RP2350 boot ROM's `flash_range_erase` + `flash_range_program` (via `rp235x-hal::rom_data`). The wrapper disables interrupts during the erase/program sequence because the XIP region isn't readable while the QSPI is in serial command mode. See the comments in `crates/firmware/src/flash_store.rs` for the exact sequencing.

## Hybrid signing contract

Recap, but see [PROTOCOL.md](PROTOCOL.md) for byte-exact details:

```
LABEL  = 32-byte constant (OpenSK/libraries/crypto/src/hybrid.rs::LABEL)

prehash = SHA-256(LABEL || msg)
ecdsa   = SignRFC6979(ecdsa_sk, prehash)
ecdsa_der = DER(ecdsa)

mu  = SHAKE-256( tr || 0x00 || 0x00 || LABEL || msg || ecdsa_der , 64 )
       where tr = SHAKE-256(pk_encode(mldsa_pk), 64)
rnd = 0^32            (FIPS 204 deterministic variant, both ports;
                       an earlier revision used SHA-256(LABEL || msg || ecdsa_der))

mldsa_sig = MLDSA::sign_mu_deterministic(sk, mu, rnd)

wire = ecdsa_der || mldsa_sig    (no length prefix -- receiver
                                   parses the inner DER length to
                                   know where ECDSA ends)
```

The `0x00 || 0x00 || LABEL` prefix inside the mu is FIPS 204's algorithm-2 framing for the empty CTAP context, with `LABEL` as our pre-hash message. We pass `Some(b"")` to `MuBuilder::do_init`; the lowmem crate handles the rest.

## Cargo-feature variant selection

The security level is chosen in one place: `crates/signer-core/src/mldsa_alg.rs` (`pqf-signer-core`), whose `#[cfg(feature = "mldsaXX")]` re-exports and constants the firmware's `crates/firmware/src/mldsa_alg.rs` re-exports wholesale. Everything downstream -- `ctap2.rs`, `core1_signer.rs`, `credential_id.rs` -- just imports `MLDSA`, `MLDSA_PK_LEN`, `MLDSA_SIG_LEN`, `COSE_ALG_HYBRID_MLDSA` and is variant-agnostic.

The composite COSE ids live there too: `COSE_ALG_MLDSA44_ES256` / `COSE_ALG_MLDSA65_ES256` / `COSE_ALG_MLDSA87_ES384` (`-54` / `-55` / `-56`, the draft-ietf-jose-pq-composite-sigs-04 requests, still provisional), one definition per level, with `COSE_ALG_HYBRID_MLDSA` set to this build's. `pqf-signer-core` is the one crate that the firmware, the TrustZone Secure image (`crates/fw-secure`) and both host-test crates all link, which is why the ids sit in a crate that otherwise never sees the wire encoding. The C port's equivalents are in `c/firmware/src/hybrid.h`. See [PROTOCOL.md](PROTOCOL.md#cose-algorithm-identifiers).

The three features are mutually exclusive. A `compile_error!` at the top of `crates/signer-core/src/mldsa_alg.rs` fires for any combination of zero / multiple. See [BUILD.md](BUILD.md) for build invocations.

## Why no `defmt`, no `probe-rs`, no panic-handler beyond `panic-halt`?

The Tiny 2350 doesn't expose SWD on a header by default, and a cased production token exposes nothing at all -- so for the Rust firmware the diagnostic path is the USB CDC class or the LEDs. Keeping the dependency footprint minimal also helps the binary fit comfortably below the 4 MB flash budget with `lto = "fat"` and per-package `opt-level = 3` for the crypto crates.

If a panic does happen the device falls into `panic-halt`'s infinite loop, and the host sees the USB endpoint disappear. Power-cycle to recover.

A `defmt` over USB CDC channel would be welcome and is a candidate for a future phase -- see [TESTING.md](TESTING.md) for the rough idea.

**Both ports have since gained a real debugger over the same cable**, the GDB stub: a C build with `-DPQF_GDB_STUB=ON` (or a Rust build with `--features gdb_stub`) links a GDB remote-serial-protocol stub served on a second CDC interface, so `arm-none-eabi-gdb` can set breakpoints, single-step, and read registers/memory on a **sealed, SWD-less token** -- no probe, no opened enclosure. It uses ARMv8-M monitor-mode debug (the DebugMonitor exception handler *is* the debugger) with FPB comparators for breakpoints, and is silicon-validated on the Feitian RP2350. It is a **debug-build-only** flag, default off and excluded from production images, because it is an unauthenticated read/write/execute primitive over USB. In such a C build a compiled-in `BKPT` (a pico-sdk panic) no longer wedges the device dark either -- it parks halted and waits for a debugger to attach and look around. Details, constraints, and the security rationale: [`GDB_DEBUG.md`](GDB_DEBUG.md). Nothing above changes for a build without the flag or for any production image of either port.

## The C port (`c/firmware/`)

A complete second implementation of this firmware in C, at full CTAP
2.1 command-surface parity with the Rust build (the Rust firmware is
its parity base -- where the two could diverge, the C matches the
Rust's observed wire behaviour). Architecturally it maps one-to-one:

| Concern | Rust | C port |
| --- | --- | --- |
| Runtime | `rp235x-hal` + `cortex-m-rt` | pico-sdk |
| USB | `usb-device` + custom FIDO HID class | TinyUSB composite (CDC banner + FIDO HID; debug builds add a 2nd CDC for the GDB stub -- [`GDB_DEBUG.md`](GDB_DEBUG.md)) |
| Crypto | bc-rust ML-DSA + RustCrypto (p256, sha2, aes) | vendored OpenSSL 3.5 (`openssl-mini/`: BN, EC/P-256, ML-DSA, SHA-2/3, AES) |
| CBOR | `pqf-cbor` (crates/cbor) | `pqcbor` (c/cbor) -- same RFC 8949 subset |
| Long ops | `core1_signer` worker + KEEPALIVE pump | `core1_signer.c` -- same FIFO + spin-with-tick contract |
| Persistence | `flash_store.rs`, three sectors (PIN/config + resident slots, large blobs, master keys), schema v12, plus optional overflow resident-credential sectors | three sectors: device keys/PIN/config, resident credentials, large blobs, plus optional overflow resident-credential sectors |
| Board layer | `src/board/` cargo features | `src/board.c` + CMake `-DPQF_BOARD` |
| Host testing | `cargo test` (host-target units) | `c/firmware/test/` -- protocol modules + vendored crypto compiled on the host against RAM-backed platform stubs |

The platform seam pattern is the load-bearing idea on the C side:
every hardware dependency (TRNG, QSPI flash, the core-1 signer) is a
small interface whose firmware implementation lives in one `.c` file
and whose host-test implementation is a stub -- so the entire protocol
stack runs and is regression-tested on the development machine, and
the device build swaps in the real platform underneath without
touching protocol code. (This mirrors what the Rust gets from cargo's
host-vs-target compilation for free.)

Both ports use the identical 161-byte credentialID layout (the
encrypted plaintext carries the credProtect policy byte at [96] so the
policy is enforceable on non-resident credentials). The one deliberate
identity difference is the AAGUID -- the C ships its own so an RP can
tell the implementations apart; a credentialID only ever decrypts
under the master key of the device that minted it, so even with the
same layout the two never cross-decrypt.
