# pqc-fido firmware -- audit findings & fix backlog

> Point-in-time record, kept for its findings. Dates and line numbers
> are as of the date in the text; the current tree has moved on. Start
> from [docs/GETTING-STARTED.md](../../GETTING-STARTED.md) for the
> present state.

> **Provenance and staleness.** This audit was produced on 2026-06-23 and
> lived only on a development branch until it was moved here during
> the 2026-08-14 branch consolidation, so it was effectively invisible. It is
> a point-in-time document: the tree has moved a long way since, and some
> findings are known to be fixed already (the `OPENSSL_cleanse` dead-store
> and the XIP/QMI slow-mode bug among them). **Re-verify every finding and
> every line number against the current tree before acting on it.** Nothing
> here has been re-checked as part of the move.

> This backlog was produced by a static security + correctness audit (2026-06-23) of the hybrid post-quantum FIDO2 authenticator firmware; it is self-contained, and the checked boxes record what was subsequently fixed.

**Scope of audit:** the Rust port (`crates/firmware`) and the C port (`c/firmware`). Vendored crypto (`c/firmware/openssl-mini/` -- OpenSSL BN/EC/ML-DSA/AES/SHA/Keccak internals, and the `bc-rust` ML-DSA crate) was treated as a black box: only the project-authored `pqf_*` glue and how the firmware *uses* the crypto were reviewed.

**Result:** **52 bugs** (2 critical, 8 high, 17 medium, 25 low), **6 features**, **17 misc**, each checked against the code, with duplicates across the two ports merged.

All findings cite specs only -- CTAP 2.1 / FIDO2, WebAuthn, RFC 8949 (CBOR), RFC 6979 (deterministic ECDSA), FIPS 204 (ML-DSA), RFC 8032 (Ed25519), COSE (RFC 9052/8152).

---

## WARNING: Read before you touch anything

The ground rules the remediation work was done under:

1. **Re-verify every line number against the current tree first.** These citations are point-in-time; `grep` for the described code, don't trust the line number blindly.
2. **Clean-room provenance is mandatory and is itself a finding (see M1).** Describe all behaviour against the specs above. **Never** name, cite, or compare against any external implementation (libfido2, authenticator-rs, ctap2-rs, yubico/yubikey, solokeys, OpenSK source, sk-cbor, etc.) in code, comments, docs, **or commit messages**. Remove any "mirrors / parity with / byte-for-byte" phrasing you touch.
3. **No hardware in the loop.** The audit and its remediation were static: nothing was flashed or forced into BOOTSEL as part of it, so every fix had to be reasoned out and covered by host-side tests where possible.
4. **Two ports, keep them honest.** The README claims the C port matches the Rust port byte-for-byte except for documented differences (independent AAGUID; 145-byte Rust vs 161-byte C credentialID). Several findings are *undocumented* parity drift -- when you fix one port, decide deliberately whether the other needs the same change, and update the parity claim if it's no longer true.
5. **Target reality:** `thumbv8m.main-none-eabihf`, `panic=abort`, `overflow-checks=false` in release. A 32-bit `usize`. An arithmetic overflow or a slice `start>end` is a hard panic = device brick, not a caught error. ~520 KiB SRAM. No stack canaries on the C side.

### Build / test quick reference

```bash
# Rust firmware (default = ML-DSA-65 on Pimoroni Tiny 2350)
cd pqc-fido && cargo build --release
#   variants: --no-default-features -F mldsa44|mldsa65|mldsa87,board_tiny2350|board_xiao_rp2350|...
#   ELF -> UF2: picotool uf2 convert -t elf target/thumbv8m.main-none-eabihf/release/pqc-fido pqc-fido.uf2 --family rp2350-arm-s

# C port (pico-sdk + TinyUSB + openssl-mini)
cd pqc-fido/c/firmware && cmake -B build -DPQF_BOARD=tiny2350 && cmake --build build
#   (today: ./build-c.sh from the repository root; see docs/BUILD.md)
#   host test harness lives in c/firmware/test/ and c/firmware/openssl-mini/test/

# NOTE: the Rust parity base currently has ZERO unit tests (finding M-repo). Adding host-target
# tests behind a flash/TRNG stub is part of the work, not optional polish.
```

### How findings are labelled

`[C1]` critical / `[H1]` high / `[Mn]` medium / `[Ln]` low / `[F1]` feature / `[X1]` misc. Each bug lists **Where / Problem / Fix**. Check the box when done.

---

## Suggested order of work

1. **`C1`, `C2`, `H1` (hybrid.c buffer)** -- the two unauthenticated C stack overflows and the C functional showstopper. All three are small, contained, and the C port cannot register a hybrid credential until `H1` lands. This is the natural first PR.
2. **Flash + PIN-counter durability** (`H2`, `H3`, plus `M`-level multicore/atomicity items) -- these brick devices or defeat brute-force protection.
3. **Rust protocol-correctness highs** (`H4` UV/credProtect spoof, `H5` CBOR DoS, `H6` channel arbitration, `H7` TRNG health bits).
4. **Error-code discipline + stateful-session binding mediums**, then the long tail of lows.
5. **M1 (provenance)** can and should be done continuously as you edit each file.

---

## Bugs to fix

### Critical (2)

#### - [x] `[C1]` (C) Unauthenticated remote stack buffer overflow in C PIN decrypt paths (pin_decrypt has no output-capacity bound)

- **Where:** `c/firmware/src/pin_protocol.c:48-69; call sites client_pin.c:215-218 (got[64], getPinToken/0x05 -- no MAC gate), client_pin.c:186-189 (pin[80], setPIN/0x03), client_pin.c:270-271 (pin[80], changePIN/0x04)`
- **Problem:** pin_decrypt() writes the full decrypted length (in_len for v1, in_len-16 for v2) into the caller's stack buffer with no out_cap parameter and no upper bound on the attacker-supplied ciphertext length (pinHashEnc 0x06 / newPinEnc 0x05 are validated only for is_bytes and %16==0; the decoder caps them only at the 7609-byte transport buffer). The length/policy checks (got_len<16, pin_len<64) run AFTER pin_decrypt has already written. getPinToken (0x05) reaches verify_pin_hash_enc with NO prior MAC verification, gated only by pin_is_set, so a peer that merely knows a PIN exists can smash got[64] with a 256+ byte pinHashEnc. setPIN is reachable with no PIN set; the pinUvAuthParam MAC on setPIN/changePIN is not a barrier because the shared secret is derived from the platform's own keyAgreement point, so any host can forge a valid MAC over an arbitrarily long block-aligned ciphertext. On bare-metal Cortex-M33 with no stack canary this is straightforwardly memory-unsafe: DoS at minimum, plausibly code execution / full key compromise.
- **Fix:** Give pin_decrypt an explicit out_cap parameter and refuse to write past it; propagate the cap into pqf_aes256_cbc_decrypt. Independently, validate the ciphertext length BEFORE decrypting at every call site: pinHashEnc must be exactly 16 (v1) / 48 (v2); newPinEnc exactly 64 (v1) / 80 (v2) -- matching the exact-length checks the Rust port already performs (client_pin.rs:796-797, 843-849, 936-939).

#### - [x] `[C2]` (C) Unauthenticated remote stack buffer overflow in C GetAssertion hmac-secret salt decryption (salts[64])

- **Where:** `pqc-fido/c/firmware/src/ctap2.c:917-919`
- **Problem:** handle_get_assertion decrypts the attacker-supplied saltEnc into a fixed uint8_t salts[64] via pin_decrypt with se_len fully attacker-controlled and unbounded. The salts_len in {32,64} guard is evaluated AFTER pin_decrypt (short-circuit && runs pin_decrypt first), so it cannot prevent the write. The preceding saltAuth pin_verify() is not a barrier: the shared secret is derived from the platform-supplied keyAgreement key, so the sending host always knows it and can compute a valid saltAuth over an arbitrarily long block-aligned saltEnc. hmac-secret is reachable with no PIN set. A ~4096-byte block-aligned saltEnc overflows salts[64] by ~4 KiB, overwriting cred_random, the shared secret, and the return-address region -- remote, no auth, single GetAssertion frame.
- **Fix:** Before pin_decrypt, require se_len <= sizeof(salts) and exactly the protocol-legal sizes (v1 se_len in {32,64}; v2 se_len in {48,80}); validate the salt count before decryption, not after. Better: give pin_decrypt an out_cap and have it refuse to overrun.

---

### High (8)

#### - [x] `[H1]` (Rust+C) Flash store has no journaling/A-B atomicity: a power-loss during the routine erase->program window wipes the device master keys (all credentials lost)

- **Where:** `crates/firmware/src/flash_store.rs:465-495 (write_sector); restore path ctap2.rs:310-355. C equivalent: c/firmware/src/flash_store.c commit() (~120-123) / resident_store.c commit()`
- **Problem:** write_sector() erases then programs the single store sector with no second copy, journal, or commit marker. Between erase completion and the first program page, the header magic is 0xFFFFFFFF, so a reboot makes read_sector() return None, driving CredStore::load down the cold-boot path that regenerates fresh TRNG master keys (key_handle_aes_key/hmac_key). Because every credentialId decrypts only under its minting device's master keys, regenerating them makes ALL previously issued credentials permanently undecryptable. The whole sector is rewritten even for a trivial mutation -- every GetAssertion bumps the counter via bump_counter->persist -- so a power glitch during a routine login (not just registration) can brick all credentials.
- **Fix:** Make the update atomic: double-buffer with two store sectors and a monotonic generation counter (write the new image to the inactive sector, only treat it as current once fully programmed), or at minimum keep master keys in a separate sector rewritten only on first-boot/Reset so counter-bump persists cannot endanger them. Write the magic LAST so a torn program yields an invalid (not falsely-valid) header.

#### - [x] `[H2]` (C) C hybrid_sign staging buffer too small to sign hybrid attestations -- hybrid MakeCredential always fails

- **Where:** `c/firmware/src/hybrid.c:58-65, 109-110 (called via credential_sign -> core1_hybrid_sign; error surfaces at ctap2.c:517-519)`
- **Problem:** hybrid_sign stages LABEL||msg[||der] in a fixed static uint8_t labelled[640] and rejects anything larger (if 32 + msg_len + PQF_P256_MAX_SIG_DER > sizeof labelled return -1). For MakeCredential the signed message is authData||clientDataHash, and authData embeds the attestedCredentialData COSE key carrying the full ML-DSA public key (1952 B for ML-DSA-65, 2592 B for ML-DSA-87). msg_len is therefore ~2000+ bytes, the guard trips, and every hybrid MakeCredential fails with CTAP2_ERR_OTHER. The C port cannot register a single hybrid credential -- the product's flagship PQC feature is non-functional on this port. GetAssertion is unaffected (no attestedCredentialData). The in-code comment claiming 'a few hundred bytes at most' is wrong for attestation; ctap2.c already sizes its own buffers at PQF_HYBRID_PK_LEN+512/+600.
- **Fix:** Size the labelled buffer (and the hybrid_verify staging buffer) to the worst case, e.g. a shared MAX_MSG_LEN-style constant >= 4096 to match the Rust core1_signer.rs MAX_MSG_LEN. These are static .bss buffers, so the cost is one-time, not stack. Fix the misleading comment.

#### - [x] `[H3]` (Rust) Blocked PIN retry counter (0) is reset to full (8) on every reboot -- defeats the sole brute-force defence

- **Where:** `crates/firmware/src/ctap2.rs:294-298 (CredStore::load PIN restore)`
- **Problem:** On restoring PIN state from flash, retries_left is set to PIN_MAX_RETRIES whenever img.retries_left == 0 || img.retries_left > 8. But retries_left == 0 is the BLOCKED state (client_pin.rs returns ERR_PIN_BLOCKED at 0); the documented policy is '0 -> PIN_BLOCKED until Reset' with the retry counter being the only defence (no time lockout). Treating a persisted 0 as corruption and resetting it to 8 means a power cycle un-blocks a blocked authenticator, so an attacker with physical access exhausts 8 guesses, replugs, and repeats indefinitely. The erased/never-set case already returns None and goes through cold-boot, so the 0-as-corruption guard is unnecessary and harmful.
- **Fix:** Change the guard to `if img.retries_left > 8 { PIN_MAX_RETRIES } else { img.retries_left }` so a persisted 0 stays 0 (blocked) across reboots; distinguish erased-sector (None -> cold boot, retries=8) from a legitimately persisted 0.

#### - [x] `[H4]` (Rust) UV flag and credProtect/hmac-secret gating can be forged via field presence when no PIN is set

- **Where:** `pqc-fido/crates/firmware/src/ctap2.rs:1934-1992 (GetAssertion), 1594 (MakeCredential uv_happened)`
- **Problem:** The pinUvAuthParam verification block is entered only when store.pin.pin_set != 0; with no PIN set it is skipped, yet uv_present is computed purely structurally as pin_uv_auth_param.is_some() && pin_uv_auth_protocol.is_some(). Any garbage bytes in 0x06 plus a 0x07 protocol id make uv_present=true. On a PIN-less device an unauthenticated host can set AUTHDATA_FLAG_UV, bypass credProtect level 3 (cred_protect==3 && !uv_present) and level 2, and obtain the with_uv cred_random for hmac-secret -- a user-verification spoof / credProtect bypass. Per CTAP 2.1 sec. 6.1/sec. 6.2 a present pinUvAuthParam on a clientPin-capable but PIN-less authenticator must return CTAP2_ERR_PIN_NOT_SET (0x35), and UV must never be asserted without a successful verification.
- **Fix:** When pinUvAuthParam is present but no PIN is set, return CTAP2_ERR_PIN_NOT_SET (0x35). Derive uv_present/uv_happened only from a boolean set inside a verification path that actually succeeded, never from field presence.

#### - [x] `[H5]` (Rust) Unbounded Vec::with_capacity from attacker-controlled CBOR array/map count -- heap-exhaustion DoS

- **Where:** `crates/cbor/src/lib.rs:664 (array), 673 (map)`
- **Problem:** decode_with_arg pre-allocates Vec::with_capacity(arg as usize) using the count from the item header before reading any element. arg can be up to 0x04000000 (5-byte header) or larger; Value is >=40 bytes, so a tiny well-formed input requests a multi-gigabyte allocation the RP2350's ~520 KB SRAM cannot satisfy. With panic=abort the allocator error path aborts the firmware -- a remotely-triggerable DoS on every CBOR parse, no PIN or user presence required.
- **Fix:** Do not size the Vec from arg. Use Vec::new() and let it grow, or clamp the pre-reserve to min(arg as usize, c.buf.len() - c.pos) (a tight upper bound: each array element needs >=1 byte, each map entry >=2). Apply to both arms.

#### - [x] `[H6]` (Rust) No CTAP HID channel arbitration: a frame on any other CID destroys the in-progress reassembly (ERR_CHANNEL_BUSY missing)

- **Where:** `crates/firmware/src/ctaphid.rs:138-231 (esp. 203, 214-216)`
- **Problem:** The transport keeps a single global reassembly slot rx: Option<InboundMsg> with no per-channel state. An INIT for a different channel overwrites self.rx, silently discarding another channel's transaction. Worse, the continuation path calls self.rx.take() UNCONDITIONALLY before the CID guard, so a single stray/foreign continuation frame on any other channel wipes the active channel's in-flight reassembly. ERR_CHANNEL_BUSY (0x06) is never emitted. Per CTAP 2.1 sec. 11.2.4 frames on a non-active channel must be answered ERR_CHANNEL_BUSY and the active transaction preserved. Any second host process can abort/corrupt another channel's FIDO transaction.
- **Fix:** Track the owning CID of the active transaction. On a non-broadcast INIT, or any continuation whose CID != active CID while a transaction is in progress, reply ERR_CHANNEL_BUSY (0x06) WITHOUT consuming self.rx (peek with as_ref() first, or take() only inside the matched arm). Define ERR_CHANNEL_BUSY = 0x06.

#### - [x] `[H7]` (Rust) TRNG ignores hardware health-test bits (AUTOCORR_ERR/CRNGT_ERR/VN_ERR) -- silent weak keys or permanent hang

- **Where:** `crates/firmware/src/trng.rs:81-88 (collect_ehr poll), 30-88 (fill)`
- **Problem:** collect_ehr polls only RNG_ISR bit 0 (EHR_VALID) and never reads the on-die continuous health-test error bits. Two failure modes: (1) AUTOCORR_ERR latches the RNG off until reset, so EHR_VALID never re-asserts and the poll spins forever, hanging whichever core called fill() (boot serial, master-key gen, PIN tokens, P-256/ML-DSA keygen) -- a DoS with no timeout. (2) On a transient CRNGT/VN failure, suspect low-entropy data still surfaces in EHR_DATA and is used verbatim for master keys, ECDSA scalars, ML-DSA seeds, IVs, and PIN tokens. fill() is the RNG behind the entire root of trust.
- **Fix:** After EHR_VALID, read RNG_ISR; treat AUTOCORR_ERR/CRNGT_ERR/VN_ERR as failure -- discard the block, SW-reset, retry a bounded number of times, and surface a hard error (refuse to boot/operate) if it persists rather than spinning or using the data. Add a bounded timeout to the EHR_VALID poll and a startup health self-test before first key generation.

#### - [x] `[H8]` (Rust) largeBlobs read: integer overflow in offset+length causes a panic-abort DoS (no auth required)

- **Where:** `pqc-fido/crates/firmware/src/large_blobs.rs:261-267 (C equivalent large_blobs.c:217-227 is non-exploitable -- encoder backstops it)`
- **Problem:** On the read path off is bounded but len = req.get_len as usize is taken straight from the u32 get field with no upper bound. end = (off+len).min(arr.len()) overflows on the 32-bit target (overflow-checks=false, panic=abort): with off small and len near u32::MAX, off+len wraps below off, end becomes < off, and arr[off..end] panics (start>end is an unconditional panic regardless of overflow-checks). Concrete trigger on the default 17-byte array: offset=1, get=0xFFFFFFFF. LargeBlobs reads need no PIN/permission, so any host can halt the device with one frame. (The C port computes the same overflow but cbor_w_bytes bounds-checks against resp_cap and latches an error before the memcpy, so it only returns the wrong error code, not an OOB -- a separate low item.)
- **Fix:** Compute end = off.saturating_add(len).min(arr.len()) to eliminate the wrap, or reject get larger than the remaining array with CTAP1_ERR_INVALID_LENGTH (0x29) per CTAP 2.1 sec. 6.10.3. On C, reject oversized get before computing end so it returns INVALID_LENGTH rather than relying on the encoder backstop.

---

### Medium (17)

#### - [x] `[M1]` (Rust+C) Flash erase/program on core 0 does not lock out core 1, which executes the signing worker from XIP flash

- **Where:** `crates/firmware/src/flash_store.rs:380-400, 448-461, 465-495; C: c/firmware/src/resident_store.c:84-96, flash_store.c:101-124,194-201, large_blobs.c:105`
- **Problem:** erase_sector/program take QSPI out of XIP and use only cortex_m::interrupt::free / save_and_disable_interrupts, which mask interrupts on the CALLING core only. Nothing parks core 1 via multicore_lockout / flash_safe_execute. Per the RP2350 ROM docs, while flash is in direct mode any XIP access from the other core returns a bus fault. Core 1 spins in its signer worker whose .text lives in XIP flash (no ramfunc relocation; the Rust module doc's claim that code runs from RAM via #[link_section=".data"] is false -- that attribute applies to data, not functions). Every persist() (MakeCredential insert, GetAssertion counter bump, delete, update, wipe, persist_pin, large-blob write, first-boot provisioning) races a core-1 fetch in the ~tens-of-ms erase/program window. The Rust instance could not be confirmed statically (severity lowered to medium there), but the missing lockout is real in both ports; the C comment only argues no flash write happens during a sign, not during commits while core 1 is parked.
- **Fix:** Coordinate the cores around every flash op: signal core 1 to spin in a RAM-resident parking routine and acknowledge before erase/program, then release. Place the core-1 park routine AND the flash erase/program sequence in RAM (true ramfunc) so neither core fetches from XIP during the op. On C, use pico-sdk flash_safe_execute() or multicore_lockout_victim_init + start_blocking. Verify with objdump that the symbols land in RAM.

#### - [x] `[M2]` (Rust+C) Rust does not zeroize decrypted PINs, shared secrets, or recovered private keys; C uses plain memset() subject to dead-store elimination

- **Where:** `crates/firmware/src/client_pin.rs:807-817, 879-892 + credential_id.rs:205, 276 (plaintext[96]); C: client_pin.c:192,200-201,226,273,279-280 + pin_protocol.c:38-44 + pqf_hmac_sha256.c:70-71,95-97`
- **Problem:** Rust: SharedSecret is Copy with no Drop/Zeroize; the decrypted PIN `plain`, `supplied_hash`, and the credential_id plaintext[96] (holding the ECDSA scalar / ML-DSA seed) are dropped without wiping; CredentialSource carries the private scalar/seed with no Zeroize. C: all secret clearing uses plain memset(), which a conforming optimizer may elide as a dead store on function-local buffers not subsequently read (decrypted PIN, SHA-256(PIN), got, HKDF PRK/Z, HMAC key-pads), leaving cleartext PIN/PIN-hash/shared-secret/HMAC material on the stack. Both ports thus leave secrets resident after use, lengthening the window for a memory-disclosure or physical attack.
- **Fix:** C: add a single pqf_cleanse()/secure_zero() helper (volatile-pointer loop or explicit_bzero) and use it for every secret buffer in client_pin.c, pin_protocol.c, credential.c, pqf_hmac_sha256.c. Rust: derive zeroize::Zeroize/ZeroizeOnDrop (or manual wipe) on SharedSecret, CredentialSource, and the decrypted plain/supplied_hash/plaintext locals.

#### - [x] `[M3]` (Rust+C) CBOR decoder accepts non-canonical CBOR (non-shortest-form ints, out-of-order and duplicate map keys) -- violates CTAP 2.1 sec. 6 reject-on-non-canonical

- **Where:** `crates/cbor/src/lib.rs:608-630, 672-680; C: pqc-fido/c/cbor/pqcbor.c:79-122`
- **Problem:** decode_arg accepts any well-formed length encoding (0x18 0x05 -> Uint(5)), and the map arm accepts entries in any order and with duplicate keys without rejection; the C pqcbor_read_head behaves identically. CTAP 2.1 sec. 6 requires authenticators to require canonical CBOR and return CTAP2_ERR_INVALID_CBOR otherwise. Both decoders resolve duplicate keys by first-match, so security impact is bounded (the authenticator is the trust boundary), but it is a real conformance/parser-differential gap that strict clients/test suites expect to be rejected. The Rust instance alone would rate low; treated here as medium given it spans both ports and is a stated spec requirement.
- **Fix:** Enforce minimal-length argument encoding (reject ai 24 with value <24, ai 25 with value <256, etc.), reject duplicate map keys, and optionally reject non-ascending keys, returning CTAP2_ERR_INVALID_CBOR / PQFIDO_ERR_CBOR. Apply in both decode_arg and pqcbor_read_head (and the cbor_read.h head used by cbor_raw_map_value). Since all decode errors already fold to INVALID_CBOR, enforcement is cheap. Alternatively document the relaxed reader as in-scope and confirm safe handling everywhere.

#### - [x] `[M4]` (Rust+C) MakeCredential ignores excludeList -- never returns CTAP2_ERR_CREDENTIAL_EXCLUDED

- **Where:** `pqc-fido/crates/firmware/src/ctap2.rs:1249-1404; pqc-fido/c/firmware/src/ctap2.c:243-298`
- **Problem:** emit_make_credential / handle_make_credential never read map key 0x05 (excludeList); no CTAP2_ERR_CREDENTIAL_EXCLUDED (0x19) constant exists. WebAuthn's excludeCredentials guarantee (preventing duplicate enrollment of one authenticator to an account) is silently violated: an RP sending excludeList gets a brand-new credential instead of 0x19 even when a matching resident credential exists. The authenticator can decrypt its own credentialIDs and index residents by rp_id_hash, so exclusion is implementable; it is simply absent in both ports.
- **Fix:** Parse excludeList (0x05); for each id of CREDENTIAL_ID_LEN attempt decrypt against rp_id_hash, and on any match return CTAP2_ERR_CREDENTIAL_EXCLUDED (0x19) after the user-presence check (gated on credProtect/UV visibility rules). Coordinate the two ports for parity.

#### - [x] `[M5]` (Rust+C) MakeCredential emits the credProtect extension on hybrid builds in C but deliberately omits it in Rust (authData byte divergence + ML-DSA-87 maxMsgSize risk)

- **Where:** `pqc-fido/c/firmware/src/ctap2.c:472-488; pqc-fido/crates/firmware/src/ctap2.rs:1798-1803`
- **Problem:** Rust suppresses the credProtect authData extension output for hybrid ML-DSA (line 1798: cred_protect_policy>0 && !is_hybrid) to stay under the 7609-byte maxMsgSize for ML-DSA-87. The C port has no such suppression: out_cp is true whenever the RP sent a credProtect input, regardless of alg, so C emits credProtect even on a hybrid MakeCredential. The README says where Rust diverges from a literal spec reading C 'matches Rust's bytes, not the spec' -- here it does not. The two ports produce different authData bytes/ED flag/length for a hybrid credProtect request, and on ML-DSA-87 C risks the very maxMsgSize overflow the Rust omission avoids.
- **Fix:** Mirror the Rust hybrid suppression in C: skip the credProtect extension output when the chosen alg is the hybrid COSE alg (at least the -50 variant). Alternatively, if suppression is no longer needed, remove it from Rust so both emit it.

#### - [x] `[M6]` (C) C port never regenerates the key-agreement key after a failed PIN attempt -- weakens per-attempt throttling

- **Where:** `c/firmware/src/client_pin.c:209-235 (verify_pin_hash_enc; regen only at boot, client_pin.c:59)`
- **Problem:** verify_pin_hash_enc decrements the retry counter on a wrong PIN but never calls regen_key_agreement(), which runs only at boot. CTAP 2.1 sec. 6.5.5.6/sec. 6.5.5.7 require a fresh key-agreement key after a failed PIN verification so the platform must perform a new ECDH handshake before each retry. The Rust base does this (client_pin.rs:874, 952). A single getKeyAgreement handshake can be reused for all 8 guesses, weakening online brute-force throttling and diverging from the parity base.
- **Fix:** Call regen_key_agreement() inside verify_pin_hash_enc() on the wrong-PIN branch after decrementing retries, matching client_pin.rs:874/952.

#### - [x] `[M7]` (C) PIN retry counter decremented AFTER the comparison, not before -- power-interruption refunds the guess

- **Where:** `c/firmware/src/client_pin.c:212-234 (verify_pin_hash_enc)`
- **Problem:** verify_pin_hash_enc checks retries==0 up front, then decrypts and compares, and only on mismatch decrements and persists the counter. CTAP 2.1 sec. 6.5.5.7 requires decrementing AND persisting pinRetries BEFORE the comparison, restoring it only on a verified-correct PIN. As written, cutting power (or resetting -- the brief notes the 10s Reset gate is relaxed and there is no RTC) between compare and the flash write leaves the counter unchanged, refunding the wrong guess. With the retry counter the only brute-force defence, this undermines the sole protection. The Rust base decrements-then-persists before comparing (client_pin.rs:944-945, 863-864).
- **Fix:** Decrement and persist pinRetries to flash before decrypting/comparing pinHashEnc; reset to PIN_MAX_RETRIES on a verified-correct PIN.

#### - [x] `[M8]` (C) C cross-core result handoff lacks an acquire/release barrier on the signature payload

- **Where:** `c/firmware/src/core1_signer.c:43-86 (publish at 50-52, observe at 77); related: non-volatile request pointers at 32-38`
- **Problem:** The C handoff synchronizes only through volatile int s_state plus the SIO FIFO token and __sev(). After signing, core 1 does s_sig_len=out_len; s_state=ST_DONE; __sev(). Core 0 spins on s_state and then reads the *s_sig SRAM buffer. On dual Cortex-M33, C volatile provides no DMB ordering of core 1's stores into *s_sig before its store to s_state, nor on core 0's side after observing the flag; __sev is an event signal, not a memory barrier. Store/write reordering can let core 0 observe ST_DONE before all signature bytes are globally visible, yielding a torn/stale signature copied into the response -- intermittent and hard to reproduce. The Rust base uses AtomicU8 Release/Acquire to create the happens-before edge.
- **Fix:** Add __dmb() on core 1 after writing s_sig/s_sig_len and before storing s_state, and __dmb() on core 0 after observing DONE/ERROR and before reading the buffer; equivalently use atomic_store_explicit(release)/atomic_load_explicit(acquire) on the flag. Also make the shared request pointers volatile (or barrier-protected) so their stores cannot move after the ST_REQUESTED/FIFO publish.

#### - [x] `[M9]` (C) C dispatch reuses shared static scratch/resp buffers and keepalive state under reentry -- response corruption on pipelined input

- **Where:** `pqc-fido/c/firmware/src/ctaphid.c:219-252 (dispatch_complete)`
- **Problem:** dispatch_complete uses function-local static scratch[CTAPHID_MAX_MSG_BYTES] and static resp[CTAP2_MAX_RESPONSE] plus file-static s_keepalive_cid. The outbound send_response and the long-op tick both spin tud_task(), which can deliver a new completed OUT report and re-enter ctaphid_recv_frame -> dispatch_complete. A nested dispatch overwrites scratch/resp while the outer send is still reading them and resets s_keepalive_cid to 0 (disarming the outer op's keepalive). The documented safety argument only covers the s_active_* transaction state, not the shared static buffers. A host that pipelines a second transaction before draining the first corrupts the outer response mid-send.
- **Fix:** Make dispatch strictly non-reentrant (a re-entrancy guard that drops/ERR_CHANNEL_BUSYs inbound reports while a response is being emitted), or save/restore s_keepalive_* and avoid reusing the same static scratch/resp across nested dispatches. At minimum document and enforce the host-serialization invariant being relied on.

#### - [x] `[M10]` (Rust) PIN-hash comparison is not constant-time (plain slice !=) in changePIN and getPinToken

- **Where:** `crates/firmware/src/client_pin.rs:871 (sub_change_pin), 951 (do_get_pin_token)`
- **Problem:** Both PIN-proof paths compare the decrypted supplied PIN hash to the stored secret with supplied_hash[..] != persistent.pin_hash[..], an early-exiting byte compare that leaks, via timing, the matching-prefix length of SHA-256(PIN)[..16]. Every other secret comparison in this module uses subtle::ConstantTimeEq, and the C port uses a constant-time XOR accumulator for exactly this comparison, so the inconsistency is unintended. Since ECDH is re-handshaked per attempt, latency sampling within an allowed attempt enables byte-at-a-time recovery of pin_hash, narrowing the search below the 8-retry online limit.
- **Fix:** Compare with subtle::ConstantTimeEq at both lines: `if !bool::from(supplied_hash[..].ct_eq(&persistent.pin_hash[..]))` (lengths already validated to 16).

#### - [x] `[M11]` (Rust) Core 0 busy-waits on core 1 with no timeout; a core-1 panic/OOM hangs the whole authenticator

- **Where:** `crates/firmware/src/ctap2.rs:748-751 (opensk_hybrid_sign wait loop)`
- **Problem:** opensk_hybrid_sign spins `while !signer.is_done() { host(HostOp::Pump); nop(); }`. is_done() only goes true on STATE_DONE/STATE_ERROR set by core 1. The ML-DSA crate allocates heavily on the shared heap with no #[alloc_error_handler]; an OOM aborts via the default handler and any core-1 panic is caught by panic_halt (halts core 1 only). Core 1 then never transitions, so core 0 spins forever emitting KEEPALIVE -- the device must be replugged. The wait has no deadline, iteration cap, or fallback.
- **Fix:** Add a bounded wait (deadline beyond worst-case ML-DSA-87 sign time). On expiry, return an empty/failed signature (the caller already clears out on errored()) instead of looping forever. Install an alloc_error_handler that signals STATE_ERROR before halting, and confirm the 64 KiB core-1 stack covers ML-DSA-87 worst case.

#### - [x] `[M12]` (Rust) Stateful CredentialManagement iterators are not bound to the originating HID channel (claimed but unimplemented)

- **Where:** `crates/firmware/src/credential_management.rs:30-32, 84, 101, 373-390, 459-476`
- **Problem:** The docstring and the _cid fields claim enumeration state is invalidated by any command on a different HID channel, but _cid is captured at Begin and never read in sub_enumerate_rps_get_next / sub_enumerate_creds_get_next (the only guard is the 30 s deadline). handle_cbor does not clear cm_rp_iter/cm_cred_iter for non-CM commands. So any channel can drive another's in-flight enumeration to completion. CTAP 2.1 sec. 6.8/sec. 11.2 require stateful commands to be bound to the originating session, widening cross-context credential-metadata disclosure (compounds the stale-after-delete issue).
- **Fix:** Compare state._cid == cid in both GetNext handlers (plumb cid through as Begin already does) and drop the iterator on mismatch, or have handle_cbor clear cm_rp_iter/cm_cred_iter on any command other than the matching GetNext. Fix the docstring if binding is intentionally dropped.

#### - [x] `[M13]` (Rust) enumerateCredentialsGetNext can return a credential deleted mid-iteration (tombstoned-slot info leak)

- **Where:** `crates/firmware/src/credential_management.rs:467-539 (slot_idxs frozen 430-449; delete_slot ctap2.rs:491-496)`
- **Problem:** CredEnumState.slot_idxs freezes raw slot indices at Begin. delete_slot only tombstones (state=STATE_EMPTY) without compaction, and emit_credential_response reads store.slot(idx) and formats it with NO state==STATE_ACTIVE recheck. A deleteCredential between Begin and a later GetNext still returns the deleted credential's user.id/name/displayName and credentialID; updateUserInformation mid-iteration produces stale-vs-fresh ambiguity. Combined with the missing channel isolation this is triggerable cross-channel.
- **Fix:** In emit_credential_response, skip and advance past slots whose state != STATE_ACTIVE; or re-resolve by a stable key (credentialId) rather than raw index; or invalidate cm_cred_iter/cm_rp_iter whenever delete_slot/update_user_info mutate the store.

#### - [x] `[M14]` (Rust) enumerateCredentials response omits the required publicKey (0x08) field

- **Where:** `crates/firmware/src/credential_management.rs:510-533`
- **Problem:** getInfo advertises credMgmt:true, but emit_credential_response decrypts the credentialID into src and discards it (let _ = src;) and never adds key 0x08 publicKey (a COSE_Key), which CTAP 2.1 sec. 6.8.3 defines as part of the enumerateCredentials response. The map carries only 0x06 user, 0x07 credentialID, optional 0x0A credProtect, 0x09 totalCredentials. Spec-conformant hosts may reject the response or fail to render the public key. This is not on the brief's known-limitations list.
- **Fix:** Re-derive the ES256 COSE_Key (and the ML-DSA half for hybrid if feasible) from the decrypted credentialID and emit it under key 0x08, matching the COSE_Key shape MakeCredential produces. If hybrid recompute is too costly, at minimum emit the ES256 half and document the divergence.

#### - [x] `[M15]` (Rust) Slot store FIFO-evicts an existing credential when full and stores every (even non-resident) credential -- no CTAP2_ERR_KEY_STORE_FULL

- **Where:** `crates/firmware/src/ctap2.rs:381-423 (insert), 1716 (unconditional insert)`
- **Problem:** CredStore::insert picks the first non-active slot and, if none is free, .unwrap_or(0) overwrites slot 0. MakeCredential calls insert unconditionally -- the rk/residentKey option (0x07) is never parsed -- so even rk=false registrations consume one of the 8 finite slots, and the 9th registration silently destroys slot 0's still-valid credential with no CTAP2_ERR_KEY_STORE_FULL (0x28). The brief says non-rk credentials should not consume a slot. (The C port has the same FIFO-overwrite-slot-0 behavior; per the parity rule that is consistent, but the underlying spec gap stands -- see also the misc doc-mismatch entries.)
- **Fix:** Parse the rk option and only call insert() when rk is requested. When all slots are full and a new resident credential is requested, return CTAP2_ERR_KEY_STORE_FULL (0x28) instead of overwriting slot 0. Dedupe by (rp_id_hash, user.id) so re-registration overwrites the matching slot.

#### - [x] `[M16]` (Rust) largeBlobs/authenticatorConfig: absent pinUvAuthParam with PIN set returns ERR_MISSING_PARAMETER (0x14) instead of ERR_PUAT_REQUIRED (0x36)

- **Where:** `pqc-fido/crates/firmware/src/large_blobs.rs:163-170; authenticator_config.rs:171-178 (also CM credential_management.rs:255-261)`
- **Problem:** When a PIN is set and the request omits pinUvAuthParam, these handlers push ERR_MISSING_PARAMETER (0x14). The project's own error discipline (implemented for MakeCred at ctap2.rs:1329-1332 and GetAssertion at 1950-1953) requires ERR_PUAT_REQUIRED (0x36) when pinUvAuthParam is absent on a PIN-protected operation, reserving 0x14/0x33 for present-but-malformed. CTAP 2.1 sec. 6.10/sec. 6.11/sec. 6.8 treat 'token required, none supplied' as PUAT_REQUIRED so the host knows to obtain a token and retry. Hosts (e.g. Chrome) keying retry/permission-acquisition off 0x36 mis-handle the no-token case. The credentialManagement variant additionally forwards the raw 0x36 from check_token_permission where MakeCred/GetAssert force 0x33 for a present-but-invalid param.
- **Fix:** Return ERR_PUAT_REQUIRED (0x36) for the absent-param branch in large_blobs, authenticator_config, and credentialManagement, mirroring the MakeCred/GetAssert sites. When pinUvAuthParam is present, map any check_token_permission failure to ERR_PIN_AUTH_INVALID (0x33), not the raw helper error.

#### - [x] `[M17]` (Rust) allowList GetAssertion does not reset assertion_iter -- stale numberOfCredentials, PII over-release, dangling GetNextAssertion

- **Where:** `crates/firmware/src/ctap2.rs:2046-2072, 2320-2353`
- **Problem:** The allowList branch never clears session.assertion_iter (only the no-allowList branch sets it). A stale iterator from a prior no-allowList GetAssertion survives. multi_credentials reads iter.total>1 from the stale iterator to decide PII release, and numberOfCredentials (0x05) is emitted from the stale total. Consequences: (1) an allowList single-credential assertion without UV can wrongly release user.name/displayName PII; (2) a spurious 0x05 is returned for an allowList assertion (sec. 6.2.3 says omit for single match); (3) a GetNextAssertion after an allowList GetAssertion pops credentials from the previous (possibly different-RP) iterator, signing over the previous clientDataHash/rp_id_hash -- sec. 6.3 requires any new GetAssertion to invalidate the GetNext iterator.
- **Fix:** Set session.assertion_iter = None at the start of every GetAssertion (or in the allowList branch) so each request begins with a fresh, RP-correct iterator state.

---

### Low (25)

#### - [x] `[L1]` (Rust+C) MakeCredential/GetAssertion ignore the options map (rk/up/uv key 0x07) -- rk=false still stored resident; explicit uv=true not honored

- **Where:** `pqc-fido/crates/firmware/src/ctap2.rs:1249-1404; pqc-fido/c/firmware/src/ctap2.c:320-354`
- **Problem:** Neither port reads the options map (MakeCred 0x07, GetAssertion 0x07). Every credential is stored resident regardless of rk, and an explicit options.uv=true with no satisfiable UV is silently accepted (a weaker-than-requested ceremony succeeds) rather than failing per CTAP 2.1 sec. 6.1/sec. 6.2 (CTAP2_ERR_INVALID_OPTION / UNSUPPORTED_OPTION / OPERATION_DENIED). up=false on MakeCredential should also be rejected with INVALID_OPTION. The always-resident behavior is partly intentional per the brief, but silently ignoring rk=false and not validating uv/up is a deviation; in practice Chrome drives UV via pinUvAuthParam.
- **Fix:** Parse options 0x07 in both ports; honor rk semantics (or reject unsupported combinations), reject up=false on MakeCredential, and on explicit uv=true with no satisfiable UV return the appropriate error. Confirm Rust-base behavior first to keep parity.

#### - [x] `[L2]` (Rust+C) No per-power-cycle consecutive-failure PIN lockout; ERR_PIN_AUTH_BLOCKED (0x34) defined but never used

- **Where:** `crates/firmware/src/client_pin.rs:87 (dead constant); C: no 0x34 path in c/firmware/src/client_pin.c`
- **Problem:** CTAP 2.1 sec. 6.5.5.6 mandates a volatile counter that blocks PIN entry after 3 consecutive wrong PINs within one power cycle (CTAP2_ERR_PIN_AUTH_BLOCKED 0x34) until reboot, in addition to the persistent 8-retry counter. ERR_PIN_AUTH_BLOCKED is declared in Rust but dead; PinSession has no consecutive-failure counter; the C port omits it too. The brief's 'no time-lockout, retry counter is the only defence' plausibly covers this as intentional, but the defined-yet-unused constant suggests it was intended and left unfinished. An attacker can burn all 8 guesses in one power cycle without the spec's intermediate reboot-gate.
- **Fix:** If the per-boot lockout is desired, add a volatile consecutive-failure counter, return ERR_PIN_AUTH_BLOCKED after 3, clear on success/power cycle. Otherwise remove the dead 0x34 constant to avoid implying it is implemented. Coordinate both ports.

#### - [x] `[L3]` (C) C verify_pin_hash_enc resident_store: trusts persisted *_len fields without re-clamping (intra-struct over-read on corrupt flash)

- **Where:** `c/firmware/src/resident_store.c:98-107, 212-218`
- **Problem:** resident_store_init memcpy's the whole slot array verbatim and validates only the 8-byte header; resident_store_get copies a slot unchecked. Downstream emitters use user_id_len/user_name_len/.../cred_blob_len directly in cbor_w_bytes/memcpy. Insert paths clamp, so this is unreachable over USB -- only via a corrupted/garbage flash sector. A slot with user_id_len=255 causes an intra-struct over-read (within sizeof(resident_cred_t)) leaking adjacent slot fields into the CBOR response. Defense-in-depth gap, not wire-exploitable.
- **Fix:** On load (and/or in resident_store_get) clamp each *_len to its array cap and treat over-cap as STATE_EMPTY/zeroed.

#### - [x] `[L4]` (C) C emit_assertion to_sign[320]/auth_data[256] have no explicit bound before memcpy

- **Where:** `pqc-fido/c/firmware/src/ctap2.c:605-618`
- **Problem:** emit_assertion memcpy's auth_data (ad_len) and clientDataHash into to_sign[320] with no check that ad_len+32 <= sizeof to_sign, relying solely on the implicit auth_data[256] cap (256+32=288<320 today). The MakeCredential path DOES guard this (ctap2.c:511). Any future growth of the GetAssertion ext output or authData silently turns this into an OOB write.
- **Fix:** Add `if (ad_len + 32 > sizeof to_sign) return -1;` before the two memcpys in emit_assertion, mirroring the MakeCredential guard.

#### - [x] `[L5]` (C) C sub_get_token leaves s_token_active=true after a failed get-token-with-permissions, discarding a prior valid token

- **Where:** `pqc-fido/c/firmware/src/client_pin.c:308-321`
- **Problem:** sub_get_token calls new_token() (rotating s_token and clearing state) and unconditionally sets s_token_active=true BEFORE validating the permissions parameter. If the permissions check fails (missing/zero for 0x09) it returns CTAP2_ERR_MISSING_PARAMETER but leaves s_token_active=true with perms=0, and the previously valid token has been silently rotated/destroyed. Not auth-bypassing (perms=0 fails the required-perm check), but a malformed request invalidates a prior good token (minor DoS / forced re-auth) and leaves an inconsistent active-with-zero-perms state.
- **Fix:** Validate permissions/rpId first, then mint and activate the token: move new_token() and s_token_active=true to after all parameter validation succeeds.

#### - [x] `[L6]` (Rust) changePIN missing pin_set==0 guard lets a PIN be set without auth on a PIN-less device (Rust/C divergence)

- **Where:** `crates/firmware/src/client_pin.rs:825-894 (sub_change_pin)`
- **Problem:** sub_change_pin checks only retries_left==0 before proceeding, never persistent.pin_set. When pin_set==0, persistent.pin_hash is the all-zero PinPersistent::empty array; a host that does getKeyAgreement and derives the shared secret can send a changePIN whose pinHashEnc decrypts to [0;16], the supplied_hash != persistent.pin_hash check matches the zero stored hash, the new PIN is accepted, and pin_set is forced to 1. CTAP 2.1 sec. 6.5.5.5 requires CTAP2_ERR_PIN_NOT_SET when no PIN is set. The C port guards this correctly (client_pin.c:240), so this is an unintended Rust-vs-C divergence (security delta over setPIN is small since setPIN also needs no prior auth when pin_set==0).
- **Fix:** Add `if persistent.pin_set == 0 { out.push(ERR_PIN_NOT_SET); return; }` at the top of sub_change_pin, before the retries check, mirroring c/firmware/src/client_pin.c:240.

#### - [x] `[L7]` (Rust) GetAssertion ignores the up=false option (silent/pre-flight assertions impossible; UP flag always set)

- **Where:** `pqc-fido/crates/firmware/src/ctap2.rs:2186-2222`
- **Problem:** emit_get_assertion never parses the options map (key 0x05 up/uv); it unconditionally calls HostOp::WaitForUp and sets AUTHDATA_FLAG_UP. Per CTAP 2.1 sec. 6.2, options.up=false performs a silent assertion (browser pre-flight / conditional mediation) where the authenticator must NOT solicit presence and must clear the UP flag. This firmware always forces a presence wait and always sets UP, so silent assertions are impossible and the UP flag is wrong for up=false. (The dev-stub presence gate itself is out of scope; the missing option parsing is the defect.) The C port likewise ignores the options map.
- **Fix:** Parse the options map (0x05); when up=false, skip WaitForUp and do not set AUTHDATA_FLAG_UP; honor up's default of true otherwise.

#### - [x] `[L8]` (Rust) hmac-secret MakeCredential emits a spurious credBlob:false extension output

- **Where:** `pqc-fido/crates/firmware/src/ctap2.rs:1766-1782 (parity-4 same)`
- **Problem:** When hmac_secret_requested is true, the code unconditionally pushes a credBlob entry (value = cred_blob_accepted, false when no credBlob was sent) alongside the hmac-secret entry -- a copy/paste defect; the comment even mislabels the block. An hmac-secret-only registration gets an unsolicited credBlob:false in the authData extensions, changing the signed authData bytes versus a spec-correct response (CTAP 2.1 sec. 11/sec. 12.4: emit an extension output only for extensions actually processed). This also diverges from the C port, which emits credBlob only when the RP sent the key.
- **Fix:** Split the emissions: push credBlob only when cred_blob_len_in > 0 || cred_blob_too_long; always push hmac-secret:true independently. This also restores C parity.

#### - [x] `[L9]` (Rust) Reset does not clear the PIN/UV session (pinUvAuthToken, key-agreement key, assertion iterator)

- **Where:** `pqc-fido/crates/firmware/src/ctap2.rs:837-845 (emit_reset)`
- **Problem:** emit_reset never receives or clears the PinSession. CTAP 2.1 sec. 6.6 requires authenticatorReset to invalidate all PIN/UV state: the current pinUvAuthToken, the ECDH key-agreement key, and any in-flight stateful command (the GetNextAssertion iterator). After Reset, session.token_active, permissions, and assertion_iter persist. Mostly low because pin_set==0 after Reset skips the verification branches, but a stale assertion_iter survives and it is a latent hazard if future code consults token_active outside the pin_set guard.
- **Fix:** Pass the PinSession into emit_reset and clear token_active, permissions, permissions_rp_id_hash, assertion_iter, and regenerate/clear the key-agreement key as part of Reset.

#### - [x] `[L10]` (Rust) Missing required user.id silently accepted in MakeCredential

- **Where:** `pqc-fido/crates/firmware/src/ctap2.rs:1379-1404`
- **Problem:** If key 0x03 (user) is absent/not a map or its id is missing/empty/over 64 bytes, user_id_len becomes 0 and MakeCredential proceeds to mint a credential with no user handle. On discoverable GetAssertion the 0x04 user field is then omitted, so the RP cannot bind the assertion to an account -- the credential is unusable for passwordless login with no error at registration. WebAuthn requires PublicKeyCredentialUserEntity.id present and 1-64 bytes; CTAP 2.1 expects CTAP2_ERR_MISSING_PARAMETER.
- **Fix:** Return CTAP2_ERR_MISSING_PARAMETER when user (0x03) or user.id is absent/empty; reject user.id longer than MAX_USER_ID_LEN rather than truncating to zero.

#### - [x] `[L11]` (Rust) largeBlobKey returned on GetAssertion without verifying the credential was created with the extension

- **Where:** `pqc-fido/crates/firmware/src/ctap2.rs:2358-2364`
- **Problem:** When largeBlobKey is requested on GetAssertion, the code derives and returns a 0x07 largeBlobKey for any matched credential unconditionally -- there is no check that the credential was registered with the largeBlobKey extension (the key is deterministically derivable from credentialId+hmac_key). Per CTAP 2.1 sec. 6.2.5/sec. 12.3 the output should only be returned for credentials created with largeBlobKey support; returning it for arbitrary credentials is a minor per-credential key over-disclosure.
- **Fix:** Track (or infer) whether the credential was minted with largeBlobKey and only emit 0x07 in that case; alternatively gate on UV/presence per the spec's privacy rules.

#### - [x] `[L12]` (Rust) getInfo omits maxRPIDsForSetMinPINLength (0x10) despite supporting the setMinPINLength RP allowlist

- **Where:** `pqc-fido/crates/firmware/src/ctap2.rs:1041-1193 (emit_get_info_with_pin)`
- **Problem:** getInfo advertises minPINLength (0x0d) and the firmware supports an RP-id allowlist for setMinPINLength (MAX_MIN_PIN_LEN_RPIDS=4), but never emits key 0x10 maxRPIDsForSetMinPINLength. CTAP 2.1 sec. 6.4 expects 0x10 when the authenticator accepts an RP-id list. Hosts cannot learn the limit and may over-send, having entries silently dropped.
- **Fix:** Add `0x10 => cbor_int!(flash_store::MAX_MIN_PIN_LEN_RPIDS as i64)` to the getInfo map.

#### - [x] `[L13]` (Rust) Missing pubKeyCredParams returns UNSUPPORTED_ALGORITHM instead of MISSING_PARAMETER

- **Where:** `pqc-fido/crates/firmware/src/ctap2.rs:1554-1583`
- **Problem:** When key 0x04 (pubKeyCredParams) is entirely absent, chosen_alg resolves to None and the code emits CTAP2_ERR_UNSUPPORTED_ALGORITHM (0x26). pubKeyCredParams is a required parameter; CTAP 2.1 sec. 6.1 calls for CTAP2_ERR_MISSING_PARAMETER (0x14) when a required parameter is absent, reserving 0x26 for present-but-no-supported-alg. Error-code precision deviation, no security impact.
- **Fix:** Distinguish absent 0x04 (return CTAP2_ERR_MISSING_PARAMETER) from present-but-no-match (CTAP2_ERR_UNSUPPORTED_ALGORITHM).

#### - [x] `[L14]` (Rust) getPinUvAuthTokenUsingPinWithPermissions does not reject unsupported/unknown permission bits

- **Where:** `crates/firmware/src/client_pin.rs:645-648, 968-983`
- **Problem:** Requested permissions are parsed as u64 then narrowed via `p as u8` and stored verbatim, checked only for non-zero and that mc/ga imply an rp_id. There is no validation that the bits are a subset of supported permissions: PERM_BIO_ENROLLMENT (0x08, 'never granted' per the brief) is granted if requested, and any bit above 7 is silently truncated by `p as u8`. CTAP 2.1 sec. 6.5.5.7 requires rejecting an unsupported permission with CTAP2_ERR_UNAUTHORIZED_PERMISSION. Currently harmless (no dispatch site checks bio; high-bit truncation is benign) but a spec deviation.
- **Fix:** Before activating the token, reject if `requested & !SUPPORTED_PERMS != 0` (SUPPORTED_PERMS = mc|ga|cm|lbw|acfg), validating against the full u64 so high bits are not silently dropped.

#### - [x] `[L15]` (Rust) CTAPHID_CANCEL does not abort the in-flight CBOR transaction nor return CTAP2_ERR_KEEPALIVE_CANCEL

- **Where:** `crates/firmware/src/ctaphid.rs:332, 246-275; wait loop ctap2.rs:748-751 / main.rs Pump`
- **Problem:** CMD_CANCEL is handled by echoing an empty CMD_CANCEL response and nothing else. Per CTAP 2.1 sec. 11.2.9.1.4 CANCEL must abort the outstanding CBOR transaction and return the cancelled command's response as CTAP2_ERR_KEEPALIVE_CANCEL (0x2D), with CANCEL itself producing no direct reply. Architecturally CANCEL cannot work today: CBOR dispatch runs synchronously, and during the multi-second hybrid sign core 0 is in the Pump wait loop which only sends KEEPALIVE and never feeds inbound frames to handle_frame, so a mid-operation CANCEL is read off the wire and discarded. A user dismissing the WebAuthn prompt cannot interrupt an in-flight hybrid MakeCredential/GetAssertion.
- **Fix:** Inspect inbound frames for CTAPHID_CANCEL on the active CID during the Pump wait; on cancel, stop pumping, return the signer to IDLE (or set a cancel flag the worker observes), and emit CTAP2_ERR_KEEPALIVE_CANCEL (0x2D). At minimum document the deliberate non-support and drop the empty CANCEL echo.

#### - [x] `[L16]` (Rust) No per-channel transaction timeout: a stalled multi-frame message wedges the only reassembly slot forever (ERR_MSG_TIMEOUT missing)

- **Where:** `crates/firmware/src/ctaphid.rs:203-231`
- **Problem:** An INIT frame announcing a large BCNT but never followed by continuations leaves self.rx populated indefinitely; there is no timestamp on InboundMsg and no timeout sweep. CTAP 2.1 sec. 11.2.5.2 requires aborting a partially-received transaction after ~500 ms of inactivity with ERR_MSG_TIMEOUT (0x05), which is not defined or emitted. Because there is exactly one global reassembly slot, a single stalled host permanently blocks reassembly for every channel -- a clean DoS primitive combined with the missing arbitration.
- **Fix:** Record a last-frame timestamp on InboundMsg; in the main loop drop self.rx and emit ERR_MSG_TIMEOUT (0x05) to the owning CID once inactivity exceeds the spec timeout. Define ERR_MSG_TIMEOUT = 0x05.

#### - [x] `[L17]` (Rust) WINK request never matches: CMD_WINK constant lacks the 0x80 init-packet bit, so advertised WINK is dead

- **Where:** `crates/firmware/src/ctaphid.rs:27, 188-191, 284, 328-331`
- **Problem:** CMD_WINK = 0x08 lacks bit 7, while every other command carries it (PING=0x81, etc.). In handle_frame, cmd = head (the raw wire byte, bit 7 set for init packets), so a real WINK arrives as 0x88 and dispatch matches `0x88 == 0x08`, which fails, falling through to ERR_INVALID_CMD. WINK is advertised (CAPABILITY_WINK) but every request is rejected, making the wink_cb/LCD-wink path dead. The response builder correctly uses CMD_WINK|0x80, confirming the request-side constant is wrong.
- **Fix:** Define CMD_WINK = 0x88 (init bit set) and use Response::new(cid, CMD_WINK, &[]) for the reply, or keep 0x08 but match against CMD_WINK|0x80. Add a transport test feeding a 0x88 init frame.

#### - [x] `[L18]` (Rust) CID 0 and non-INIT commands on the broadcast CID are not rejected (ERR_INVALID_CHANNEL missing)

- **Where:** `crates/firmware/src/ctaphid.rs:186-211, 277-340`
- **Problem:** handle_frame never validates the channel id. cid==0 (reserved) is processed normally and can occupy the single reassembly slot; any command (e.g. PING) is dispatched on the broadcast CID 0xffffffff rather than only INIT. CTAP 2.1 sec. 11.2.4 requires ERR_INVALID_CHANNEL (0x0B) for cid==0 and for any non-INIT command on broadcast, which is never defined or emitted. Interacts with the arbitration gap.
- **Fix:** At the top of handle_frame reject cid==0 with ERR_INVALID_CHANNEL; in dispatch allow only CMD_INIT when cid==BROADCAST_CID and reply ERR_INVALID_CHANNEL otherwise. Define ERR_INVALID_CHANNEL = 0x0B.

#### - [x] `[L19]` (Rust) Single rx_frame buffer silently drops frames under back-pressure, corrupting multi-frame reassembly

- **Where:** `crates/firmware/src/fido_hid.rs:243-247, 256-269`
- **Problem:** Both the SET_REPORT and interrupt-OUT paths buffer exactly one inbound frame and silently drop any further frame while rx_frame is occupied. If the host streams a multi-frame CBOR message faster than the main loop drains recv_frame() (one frame/iteration), an intermediate continuation is dropped; the next continuation then mismatches expected_seq and ctaphid aborts with ERR_INVALID_SEQ. Large allowList/excludeList/credBlob/largeBlob requests can intermittently fail under USB back-pressure, especially while the loop is blocked in synchronous CBOR/crypto.
- **Fix:** Grow to a small ring of inbound frames, or respond ERR_CHANNEL_BUSY when a frame is dropped so the host can retry deterministically. At minimum document that the main loop must recv_frame() between every OUT packet.

#### - [x] `[L20]` (Rust) submit() panics core 0 on oversized message instead of returning the error it already computes

- **Where:** `crates/firmware/src/ctap2.rs:722-724 (.expect on signer.submit)`
- **Problem:** opensk_hybrid_sign calls signer.submit(...).expect("core1 sign submit"). Core1Signer::submit returns Err when msg.len() > 4096 (core1_signer.rs:182-184), but the caller unwraps it; with panic_halt this aborts core 0 and bricks the device. Unreachable today (worst-case to_sign ~3035 B for ML-DSA-87 < 4096), but a future growth (larger extension outputs, larger ML-DSA params, credBlob feeding to_sign) hard-halts the transport core instead of returning a clean CTAP error.
- **Fix:** Handle the Err: return an empty signature (caller treats that as failure) or propagate CTAP2_ERR_REQUEST_TOO_LARGE, rather than .expect(). Add a static assertion that worst-case to_sign for the selected ML-DSA feature is < MAX_MSG_LEN.

#### - [x] `[L21]` (Rust) v2 (Ed25519) credentialID encrypt path does not enforce the reserved mldsa_seed-zero invariant that decrypt enforces

- **Where:** `crates/firmware/src/credential_id.rs:205-235 (decrypt enforces at 310-315)`
- **Problem:** decrypt_credential_id rejects a v2 blob whose reserved mldsa_seed slot is non-zero as BadFormat, but encrypt_to_credential_id copies source.mldsa_seed verbatim into the v2 slot with no matching guard. A future caller with alg=-8 and a non-zero mldsa_seed would mint a v2 credentialID the same device's decrypt then permanently rejects (a dead credential). Not currently triggerable (the sole v2 caller sets mldsa_seed=0); latent defense-in-depth.
- **Fix:** When emitting v2, debug_assert!(source.mldsa_seed == [0u8;32]) and/or force the reserved slot to zero regardless of source, so encode cannot produce a blob that fails its own decode invariant.

#### - [x] `[L22]` (Rust) INIT nonce has almost no entropy (Instant::now().elapsed() is ~0) in the host client

- **Where:** `crates/ctaphid-client/src/hid/mod.rs:224-229`
- **Problem:** The 8-byte CTAPHID INIT nonce is built from a 16-bit startup counter, the 32-bit PID, and Instant::now().elapsed().as_nanos() as u16 -- the elapsed-immediately measurement is a handful of nanoseconds, so the low 16 bits contribute essentially no entropy, making the nonce effectively (salt, pid): predictable and identical across runs. The CTAPHID spec wants 8 random bytes so the host can match an INIT response on the broadcast channel to its own request; two processes can collide and accept a wrong-conversation INIT response.
- **Fix:** Fill the nonce with OsRng (the crate already depends on rand, as used for the v2 IV in pin_protocol.rs:230).

#### - [x] `[L23]` (Rust) authenticatorConfig setMinPINLength has no upper bound on newMinPINLength -- can permanently brick PIN setup

- **Where:** `pqc-fido/crates/firmware/src/authenticator_config.rs:235-252 (parse at 99)`
- **Problem:** newMinPINLength is parsed as a raw u8 and stored verbatim after only the 'must not lower' check, with no upper bound. setPIN enforces actual_len < min_pin_length and the PIN buffer caps usable PIN at 63 bytes, so setting newMinPINLength to 64..255 makes it impossible to ever set a PIN again. Once a PIN exists, an acfg-scoped token can raise the floor beyond the achievable maximum (recoverable only via authenticatorReset, which wipes all credentials). Not remotely exploitable without acfg permission.
- **Fix:** Clamp/reject newMinPINLength above a sane ceiling (e.g. 63, the max the encode buffer supports) and return CTAP2_ERR_INVALID_PARAMETER for out-of-range values, per CTAP 2.1 sec. 6.11.4.

#### - [x] `[L24]` (Rust) largeBlobs write: alwaysUv does not force authentication when no PIN is set

- **Where:** `pqc-fido/crates/firmware/src/large_blobs.rs:161-203`
- **Problem:** The write path gates auth solely on store.pin.pin_set != 0; if no PIN is set the entire pinUvAuthParam/permission block is skipped and the write proceeds unauthenticated even when store.always_uv is true. CTAP 2.1 sec. 6.10.4 requires user verification when alwaysUv is asserted. On this hardware uv-without-PIN is unachievable, so exposure is limited to the degenerate 'alwaysUv=true, no PIN' state that toggleAlwaysUv can create, but in that state a write that should be blocked is accepted (device-wide large-blob array overwritten with no auth).
- **Fix:** Require pinUvAuthParam when store.pin.pin_set != 0 || store.always_uv, returning ERR_PUAT_REQUIRED/ERR_OPERATION_DENIED appropriately when no token can satisfy it, mirroring the MakeCred/GetAssert alwaysUv handling.

#### - [x] `[L25]` (Rust) Rust do_get_pin_token / sub_change_pin do not regenerate the ECDH key on a structural decrypt failure of pinHashEnc

- **Where:** `crates/firmware/src/client_pin.rs:944-955 (also 868-869)`
- **Problem:** After decrementing/persisting the retry counter, a structural failure of secret.decrypt(&pin_hash_enc) (wrong length/undecryptable) returns ERR_PIN_INVALID WITHOUT regenerating session.key_agreement, whereas the wrong-PIN branch does regenerate it so the platform must re-handshake. sub_change_pin has the same shape. The decrement still happens so retries are not bypassed, but the per-attempt re-handshake hardening is applied inconsistently between the two PIN_INVALID exits.
- **Fix:** Regenerate session.key_agreement on the decrypt-failure path too, for consistency with the value-mismatch path (or document why only the mismatch path re-handshakes).

---

## Features to add

#### - [x] `[F1]` (HIGH / Rust+C) Implement excludeList processing with CTAP2_ERR_CREDENTIAL_EXCLUDED (0x19) in both ports

- WebAuthn's excludeCredentials is the primary mechanism preventing an RP from re-enrolling an authenticator already bound to an account. Both ports currently mint a new credential instead of returning 0x19, silently breaking the guarantee. The authenticator can decrypt its own credentialIDs by rp_id_hash, so the feature is implementable per CTAP 2.1 sec. 6.1. (Tracked as a bug above for the missing-handler defect; called out here as the feature work to close the sec. 6.1 surface.)

#### - [x] `[F2]` (HIGH / Rust) Emit publicKey (0x08) in enumerateCredentials responses

- getInfo commits to credMgmt:true, and CTAP 2.1 sec. 6.8.3 defines publicKey as a response field. Without it, spec-conformant management UIs may reject or fail to render enumerated credentials. The credentialID is already decrypted (and discarded) on this path, so the COSE_Key can be re-derived cheaply for the ES256 half.

#### - [x] `[F3]` (MEDIUM / Rust+C) Honor the options map (rk/up/uv) in MakeCredential and GetAssertion

- Closes several sec. 6.1/sec. 6.2 gaps at once: respecting rk=false (non-discoverable credentials, freeing finite slots), supporting up=false silent/pre-flight assertions for conditional mediation, and correctly failing explicit uv=true when no UV is satisfiable instead of silently downgrading the ceremony.

#### - [x] `[F4]` (MEDIUM / Rust) Persist the RP id string so enumerateRPs returns a non-empty rp.id

- enumerateRPs currently emits rp = {"id": ""} because only the rp_id_hash is stored, so management UIs cannot show a human-readable RP. CTAP 2.1 sec. 6.8.3 carries the PublicKeyCredentialRpEntity id string. The code comment already flags this as a deferred-phase placeholder.

#### - [x] `[F5]` (LOW / Rust+C) Support multi-fragment largeBlobs writes (offset != 0)

- authenticatorLargeBlobs is advertised but both ports reject offset != 0 with ERR_INVALID_PARAM, so blobs that don't fit in one CTAP transaction cannot be stored (CTAP 2.1 sec. 11.5 allows fragmented writes). Documented and parity-consistent; if full support is not desired, document the single-shot constraint explicitly in PROTOCOL.md so RP integrators do not fragment.

#### - [x] `[F6]` (LOW / Rust) Add an explicit getUVRetries (ClientPIN 0x07) arm

- 0x07 falls through to ERR_INVALID_SUBCOMMAND. For a PIN-only device with no built-in UV this is defensible per CTAP 2.1 sec. 6.5.5.2.4 (hosts query it only when a UV method is advertised), but an explicit arm makes the intent obvious and documents the no-UV posture. No functional change required.

---

## Misc / hygiene / tech-debt

#### - [x] `[X1]` (Rust+C) Clean-room provenance violated: shipped firmware source and the designated clean-room host crate name external implementations

- Multiple in-scope files breach the project's clean-room-from-spec rule by naming/citing an external implementation (the project's own rule explicitly forbids this in source, comments, and docs). Firmware Rust: credential_id.rs (8-13, 25, 115, 191, 340-342, 411, including 'byte-for-byte' and 'parity with the OpenSK reference'), mldsa_alg.rs (3, 19-20, 57), client_pin.rs (1-8, 80-81, 244-251, 340-341, 959-967), ctap2.rs:702. The designated clean-room host crate crates/ctaphid-client also violates its own directive: types.rs:19, session.rs:510 ('libfido2-aware'), make_credential.rs:74 ('Firefox/libfido2'), hid/mod.rs:108 ('YubiKey 5'). The sibling clean-room crate crates/cbor and the C files are clean. Action: rewrite all such comments to describe behaviour against CTAP 2.1 sec. 6.5 / COSE (RFC 9052/8152) / RFC 8949 / FIPS 204 / RFC 6979 / RFC 8032 directly; remove every external name, file path, line range, and 'mirrors/parity/byte-for-byte' phrasing; audit commit messages too. Highest-priority hygiene item given the project's stated invariant.

- **Resolved (2026-06-24):** the designated clean-room crate `crates/ctaphid-client` is verified clean -- no external-implementation names remain (the cited lines were rewritten in earlier provenance work; "FIDO2"/"WebAuthn" are protocol names and the single "mirror" describes the spec-defined CBOR wire shape, not an implementation). The firmware's OpenSK references are retained deliberately as attributed Apache-2.0 derivation: the clean-room-from-spec mandate scopes to the library crates (`crates/cbor`, `crates/ctaphid-client`), which are clean, not to the OpenSK-derived firmware.

#### - [x] `[X2]` (Rust+C) Stale credentialID size docs contradict the real formats (145 B Rust / 161 B C)

- Rust ctap2.rs:172-175, 1668-1685 call the credentialID a '241-byte v5/OpenSK v1 blob' though CRED_ID_LEN is 145; core1_signer.rs:81 says 147 B. C credential.h:6-12, 59 and credential.c:3 claim a '145-byte' ID 'byte-for-byte interchangeable with Rust', directly contradicting the actual 161-byte/112-byte-plaintext layout explained correctly just below (lines 24-28). The 145-vs-161 divergence itself is intended (IDs only decrypt under their minting device's keys), but the contradictory comments mislead auditors into assuming cross-port interchangeability. Update all three to the real sizes and describe layout against the specs only.

#### - [x] `[X3]` (Rust) Misleading/dead flash-store documentation and constants

- flash_store.rs:7-12, 161-162, 220 describe a 'sequential append + tombstone' design with STATE_TOMBSTONE=0x0 that is never written (delete uses STATE_EMPTY; the real model is full-sector rewrite). flash_store.rs:153-157 cite stale 352B slot / 104B header / 11 slots vs the real 432B / 240B / 8. A maintainer could reason incorrectly about power-loss/atomicity. Fix the doc to the actual model and add const assertions (size_of::<StoredCredential>()==432; HEADER_SIZE + MAX_SLOTS*size_of <= SECTOR_SIZE) to keep docs and code honest.

#### - [x] `[X4]` (Rust) Missing static layout assertions and linker guard for repr(C) flash structures

- flash_store.rs has no const layout assertions and no tests covering StoredCredential size/offsets or the sector budget; memory.x (16-27, 40-51) declares the full 4096K FLASH with no ASSERT or shortened LENGTH reserving the top two sectors (store 0x3FF000, large-blob 0x3FE000) from .text, so a large hybrid build could overlap code and have erase_sector() wipe live code with no build-time error. Add const assertions, host round-trip tests behind a cfg(test) flash/TRNG stub, and either shorten FLASH LENGTH by 8K or add an ASSERT(__flash_binary_end <= 0x103FE000) to memory.x.

#### - [x] `[X5]` (Rust) write_large_blob_sector relies on a debug_assert (compiled out in release) for its only length bound

- flash_store.rs:427-437 uses debug_assert!(array.len() <= MAX_LARGE_BLOB_LEN); in release a violation would panic on the bounds-checked slice copy. Safe today (sole caller guards at large_blobs.rs:229) but a future second caller or changed guard turns it into a runtime panic. Add a real early-return/clamp so release builds are self-protecting.

#### - [x] `[X6]` (C) C core1 result-handoff request pointers not all volatile (compiler-reordering risk on the publish)

- core1_signer.c:32-38 -- s_scalar/s_seed/s_msg/s_sig are plain (non-volatile) pointers while only s_state/s_msg_len/s_sig_len are volatile; only the opaque cross-TU FIFO call currently prevents their stores from moving after the ST_REQUESTED publish. With LTO or an inlined FIFO push, core 1 could read stale request inputs. Make all shared request fields volatile (or barrier-protected) alongside the acquire/release fix tracked in the bug list, matching the Rust submit()'s Release store.

#### - [x] `[X7]` (C) Defensive bounds gaps that are currently unreachable but one refactor from a fault

- Three low-risk hardening nits: (1) ctap2.c:825-836 no-allowList GetAssertion trusts resident_store_find_by_rp's count (documented as 'may exceed cap') without clamping to idxs[RESIDENT_MAX_SLOTS] -- add `if (nm > RESIDENT_MAX_SLOTS) nm = RESIDENT_MAX_SLOTS;`. (2) pqcbor.c:427-443 pqcbor_walk lacks the array/map element-count pre-bound that pqcbor_parse_one has (191/219) -- add the same n > remaining checks. (3) pin_protocol.c:33-37 ignores pqf_hkdf_expand return values (fixed-valid lengths today). hybrid.c:60,109 static staging buffers are non-reentrant (safe under the single-caller model). All are latent-only; fix opportunistically alongside the related bugs.

#### - [x] `[X8]` (Rust) CBOR encode/decode edge cases on the 32-bit target

- cbor/src/lib.rs: (1) encode(Nint(i64::MIN)) overflows `-1i64 - *n` (line 422); safe only because release disables overflow-checks but panics under cargo test/debug -- replace with `(*n as u64) ^ u64::MAX`. (2) Length/count fields use `arg as usize` (651/657/664/673) which silently truncates a 64-bit wire length on the 32-bit target -- reject arg > buf.len() as u64 before the cast. (3) Canonical map ordering sorts by major type first (RFC 8949 sec. 4.2.1 bytewise) not CTAP2 sec. 6 length-first; identical for the COSE_Key maps emitted today (all 1-byte keys) but would emit non-canonical bytes for any future map mixing >=24 positive keys with negative keys -- sort by encoded key bytes (len, bytes). (4) No total-item/breadth cap on decode (depth is capped at 128); a 7.6 KB input can allocate thousands of Value nodes even after the with_capacity fix -- optionally add a total-allocation budget.

#### - [x] `[X9]` (C) C CBOR decoder accepts major-7 floats / reserved simple values as opaque SIMPLE integers; stale 2048 maxMsgSize comment

- pqcbor.c:269-273 decodes half/single/double floats and reserved simple values into PQFIDO_CBOR_SIMPLE with the raw bit pattern as arg; harmless today (no handler consumes SIMPLE) but could be misread as a number -- reject or tag distinctly. ctaphid.c:155-157 comment says max body 2048 but CTAPHID_MAX_MSG_BYTES is 7609 (buffers are consistent at 7609); also stale 'Phase C-2' scope note in ctaphid.h:56-58. Doc/robustness only.

#### - [x] `[X10]` (C) ECDSA random-k vs deterministic-k and ML-DSA randomizer differ across ports; both are valid but break the documented byte-parity claim

- The C port signs the ECDSA half with random k (pqf_p256.c:183-184; the RFC 6979 path pqf_ecdsa_sig.c:49-60 is deliberately stubbed to fail) and the ML-DSA half with an empty randomizer (pqf_mldsa.c:80-82, rho_prime = SHAKE256(K||mu)), while Rust uses RFC 6979 deterministic ECDSA and a non-empty deterministic ML-DSA rnd = SHA-256(LABEL||msg||der). Both ports produce signatures any RP verifies, so there is no interop failure, but hybrid.c's 'byte-compatible with the Rust firmware' header comment is false, and the random-k ECDSA path makes signature security depend on the SDK PRNG (get_rand_64, pqf_rand.c) being CSPRNG-grade and well-seeded -- k reuse would leak the private scalar. Either implement RFC 6979 (and derive the matching ML-DSA rnd) for true parity and RNG-independence, or correct the comment to state the halves are independently valid but not byte-identical, and audit the C RNG as CSPRNG-grade. Note C's empty-rnd is also not the FIPS 204 deterministic form (0^32 absorbed).

#### - [x] `[X11]` (Rust) Internal HMAC domain-separation and v1 alg-discrimination rely on incidental properties

- credential_id.rs: cred_random, largeBlobKey, and the credentialID integrity tag all key off the single key_handle_hmac_key, separated only by differing HMAC input lengths/suffixes (113 vs 146 vs 148) rather than explicit domain tags -- a future CRED_ID_LEN or suffix change could collide them. Separately, v1 ES256-vs-hybrid is inferred by a constant-time all-zero test of the decrypted mldsa_seed (302-309) rather than an authenticated discriminator (HMAC binds the plaintext so not externally exploitable, but implicit). Also note cred_random input shape differs from the C port (Rust no prefix; C adds a 15-byte 'pqf-hmac-secret' prefix) -- device-local so not host-observable, but an internal inconsistency in functions documented as mirrors. Add explicit domain-prefix tags (or HKDF-Expand info labels) and document/assert the non-zero-seed invariant.

- **Resolved (2026-06-24):** implemented in both ports (the working note this line used to link is now [`HMAC-DOMAINS.md`](../../HMAC-DOMAINS.md); the derivation it specifies is also documented in [`PROTOCOL.md`](../../PROTOCOL.md#encrypted-credential-id-161-bytes)). All three master-MAC-keyed HMACs now carry an explicit ASCII domain prefix -- integrity tag `"pqf-cred-id"` (symmetric in encrypt+decrypt), cred_random `"pqf-hmac-secret"`, largeBlobKey `"pqf-large-blob-key"` (C's old `"lbk"` suffix removed). The labels diverge at byte index 4 (`c`/`h`/`l`) and none is a prefix of another, so the four HMAC messages (incl. cred_random uv=0/uv=1) are pairwise distinct independent of credentialID length/content -- positional separation, not incidental. The all-zero-`mldsa_seed` => ES256 discriminator is documented as integrity-tag-authenticated and guarded against minting a zero-seed hybrid (Rust `debug_assert!`; C hard `return -1`). Wire format unchanged (161 B, no schema bump); HMAC outputs change (credential-invalidating -- handled by a wipe). The Rust and C derivations are byte-for-byte mirrors. Reviewed three times for soundness and for agreement between the ports, and covered by the C `test_domain.c` host test (round-trip, pairwise distinctness, single-byte-tamper, cross-RP -- 0 failures); the firmware Rust bin can't host a test harness (no_std+no_main), so the byte-identical C test is the regression guard.

#### - [x] `[X12]` (Rust) U2F module is unreachable dead code carrying a hardcoded dev attestation private key

- u2f.rs:133-176 -- FrameOutcome::U2fMessage is matched but never constructed (CMD_MSG always returns ERR_INVALID_CMD), so the whole module and its inline BATCH_KEY (a P-256 private scalar) + cert ship in every binary for no runtime benefit. If U2F is ever re-wired, every device shares a publicly-known dev attestation key. Feature-gate the module (and the key) out of default/production builds, or add a debug_assert tripwire at the U2fMessage arm. Documented dev-only per the brief, so housekeeping not a vuln.

#### - [x] `[X13]` (Rust) authenticatorConfig forceChangePin clears pin_set instead of flagging a required change

- authenticator_config.rs:268-280 sets pin.pin_set=0 on forceChangePin=true, so the device reports clientPin=false and accepts a fresh unauthenticated setPIN -- converting 'must change PIN' into 'PIN protection removed until re-set'. CTAP 2.1 sec. 6.11.4 intends the existing PIN to stay active with forcePINChange surfaced in getInfo 0x0c so the host runs changePIN (old-PIN-authenticated). Requires an acfg token to trigger and is a documented approximation. Track a separate persistent force_pin_change flag and surface getInfo 0x0c instead.

#### - [x] `[X14]` (Rust) Host-client robustness/quality gaps in ctaphid-client

- Several low/quality items: (1) hid/mod.rs:468-494 -- a KEEPALIVE arriving mid-message triggers continue 'outer, discarding the partial buffer; the device won't re-send the init frame so the message can never complete (Timeout). Detect Cmd::Keepalive/foreign-CID in the inner loop and continue without discarding. (2) session.rs:313-335/365 -- after cancel() the cancelled op's KeepaliveCancel response is left queued; the next recv_msg for a different command mis-attributes it. Document the drain requirement or consume it in cancel(). (3) large_blobs.rs:62-92 read_array relies on a short/empty-fragment end signal (over-reads by one chunk on aligned arrays) and the doc claims a total-length field that doesn't exist; offset is cast to u32 in write auth. (4) session.rs:477-505 maybe_mint_token ignores forcePINChange (getInfo 0x0c) and surfaces a raw CTAP error instead of guiding changePIN. (5) pin_protocol.rs:325-363 decode_cose_p256 doesn't assert kty=2/alg=-25/crv=1 (on-curve check still applies, so no invalid-curve attack). Spec-strictness/diagnostics improvements.

#### - [x] `[X15]` (Rust) Board bring-up nits (XIAO/Waveshare)

- (1) board/xiao_rp2350.rs:65-66 -- GP23 (WS2812/USB power gate) is enabled as output then set_low() in two steps; into_push_pull_output() applies whatever is latched in GPIO_OUT, so after a warm/RUN-pin reset the pin can momentarily drive the rail ON, reintroducing the USB-enumeration glitch the gate exists to prevent. Use into_push_pull_output_in_state(PinState::Low) for an atomic low. (2) LCD .expect() panics (waveshare lcd.rs:173,207; spotpear 144,166) halt core 0 via panic-halt before USB comes up, so a faulty/absent panel yields a dead non-enumerating device -- consider degrading to Option<Display>. (3) Doc nit mod.rs:95-96 names SPI1/GP25 but code uses SPI0/GP21. (4) LCD first-frame full clear blocks usb_dev.poll() ~27 ms between commands (NAKed, not lost). (5) static mut LCD_SPI_BUFFER &'static mut alias is sound under the single Board::setup call site but enforced socially -- consider a StaticCell/Once guard. (6) Vestigial last_op field + _suppress_unused shims (lcd.rs:266,488-491; large_blobs.rs:277-280; credential_id.rs:412-413) are dead tech debt to remove.

#### - [x] `[X16]` (Rust) TRNG efficiency and bring-up assumptions (beyond the health-test bug)

- trng.rs: (1) next_u32/next_u64 each trigger a full 192-bit EHR collection and discard most of it (94-103), making p256 keygen/ECDH slow and multiplying exposure to unchecked EHR blocks -- buffer the 24-byte output and serve from it. (2) SAMPLE_CNT1 is set to 0x1000, ~16x fewer cycles than the 0xffff hardware default, with a comment calling it 'conservative' when a lower sample count trades entropy for speed (59-62) -- keep the default or justify/measure, and fix the comment. (3) Trng::new assumes init_clocks_and_plls un-resets the TRNG (19-25), which is not what that path does; bring-up correctness rests on an inaccurate assumption -- explicitly clear the TRNG RESETS bit and poll RESET_DONE, then correct the comment. (4) core1_signer.rs:19-20 module doc references a non-existent wait_for_done() and a stale 147 B credentialId -- fix to the actual is_done()/take_result() busy-wait and 145 B.

#### - [x] `[X17]` (Rust+C) Repo hygiene: untested parity base, no CI, gitignored Cargo.lock, and contradictory licensing docs

- (1) crates/firmware (the declared parity base) has zero unit/integration tests; all protocol-critical logic (credential_id, client_pin v1/v2 derivation, the 0x33/0x36 discipline, credProtect gating) is unverified, so regressions silently propagate to the C port that mirrors it -- add host-target unit tests behind a flash/TRNG stub. credProtect has no test in either port despite gating credential disclosure. ctaphid-client has uneven coverage (get_assertion/get_info/credential_management have no tests). (2) No CI (.github/workflows absent) despite docs implying CI-style verification -- wire up the feature-matrix builds, cargo test for pqf-cbor/pqf-ctaphid, and the C make test/KATs. (3) .gitignore line 3 unanchored 'Cargo.lock' ignores the lockfile for this binary workspace, defeating reproducible builds and the THIRD_PARTY.md audit-trail reference -- commit Cargo.lock. (4) THIRD_PARTY.md claims a `cargo deny check licenses` allow-list with no deny.toml present, references a nonexistent root LICENSE, and contradicts README/CHANGELOG (all-rights-reserved) -- reconcile. (5) docs/TESTING.md cites stale schema v6/v7 (actual v9) and resident_store.h references a non-existent host_resident_stub.c (the host path is the PQF_RESIDENT_HOST branch in resident_store.c). (6) build.sh defaults to waveshare while Cargo.toml/README default to tiny2350 -- reconcile. (7) getInfo algorithms comment (ctap2.rs:1108-1158) claims build-specific ordering the fixed -50/-49/-48 list doesn't implement; credential_management.rs pin_auth_message docstring (218-228) wrongly shows a 0x0A prefix the correct code omits -- fix before a future regression trusts it.

---

## Cross-cutting themes

These span multiple findings -- fixing one site without the systemic view tends to leave siblings unfixed.

- Constant-time discipline is applied inconsistently: Rust's PIN-hash comparison falls back to a plain slice != while the rest of the module uses subtle::ConstantTimeEq (and the C port compares the same value in constant time), and credential-ID rp_id_hash comparison is non-constant-time in both ports (benign post-HMAC). Secret zeroization is also uneven -- C uses elidable memset(), Rust derives no Zeroize at all -- so neither port reliably wipes decrypted PINs, shared secrets, or recovered private keys.
- CTAP error-code discipline (0x14 MISSING_PARAMETER vs 0x36 PUAT_REQUIRED vs 0x33 PIN_AUTH_INVALID, and 0x35 PIN_NOT_SET) is correct at the MakeCred/GetAssert callsites but diverges in largeBlobs, authenticatorConfig, and credentialManagement, which return 0x14 (or forward a raw 0x36) where the project's own convention and CTAP 2.1 require 0x36/0x33. This breaks host retry/permission-acquisition state machines that key off these codes.
- Input-length validation before decryption is the single most dangerous systemic gap: the C pin_decrypt / hmac-secret salt paths write attacker-controlled plaintext into fixed stack buffers with no out_cap and no pre-check, yielding unauthenticated stack overflows. The Rust port already does exact-length checks; adding an out_cap parameter (or per-callsite exact-length gates) is the unifying fix.
- Integer-overflow / truncation hardening on the 32-bit thumbv8m target with overflow-checks=false + panic=abort: largeBlobs offset+len overflow (panic-abort DoS in Rust, wrong-error in C), CBOR length truncation via `arg as usize`, unbounded Vec::with_capacity, and Nint(i64::MIN) encode overflow all share the same class -- values from the wire must be bounds-checked against the remaining buffer before arithmetic or allocation.
- Flash persistence and dual-core safety: non-atomic single-sector erase/program with no journaling (master-key loss on power glitch), a blocked-retry counter reset on reboot, core-0 flash ops that don't lock out the XIP-executing signing core, and a cross-core result handoff missing acquire/release barriers -- together these make the persistence + multicore path the highest-risk reliability/availability subsystem in both ports.
- CTAP HID transport conformance: no channel arbitration (ERR_CHANNEL_BUSY), no transaction timeout (ERR_MSG_TIMEOUT), no CID/broadcast validation (ERR_INVALID_CHANNEL), broken WINK dispatch, ineffective CANCEL, and single-frame back-pressure drops are a cluster of missing/incorrect transport-layer behaviors that interact (e.g. one global reassembly slot magnifies the arbitration and timeout gaps into DoS primitives).
- Stateful-command session binding: GetNextAssertion and CredentialManagement enumeration iterators are not invalidated by activity on another channel, by a new GetAssertion, or by mid-iteration deletes -- a recurring failure to scope stateful CTAP commands to their originating session, enabling cross-context disclosure and stale-credential leaks.
- Spec-canonical CBOR enforcement is absent in both decoders (non-shortest-form ints, duplicate/out-of-order map keys accepted), and re-canonicalization of pinUvAuth-signed params in credentialManagement can reject otherwise-valid non-canonical host input -- two sides of the same canonical-CBOR conformance theme.
- Clean-room provenance: shipped firmware comments and, more seriously, the designated clean-room host crate (crates/ctaphid-client) repeatedly name external implementations, contradicting the project's stated invariant -- a documentation/IP-hygiene theme spanning crypto, client_pin, and host modules.
- RNG as a single root-of-trust dependency: both ports funnel master keys, per-credential seeds/scalars, ECDSA nonces, and PIN tokens through one generator with no health-test/error surfacing (Rust ignores TRNG error bits; C's RAND_status always returns 1), and the C ECDSA half additionally depends on random-k quality where Rust uses RFC 6979.
- Parity drift: several behaviors the README claims are byte-for-byte mirrored actually diverge -- changePIN pin_set guard, key-agreement regen on failure, retry-decrement ordering, credProtect-on-hybrid suppression, PIN max-length enforcement, credBlob emission shape, ML-DSA/ECDSA nonce derivation, and cred_random domain prefix -- making the 'C matches Rust's bytes' invariant unreliable and untested.

---

## Coverage gaps -- what this static audit could NOT confirm

- No hardware was available: nothing dynamic could be exercised on the RP2350. All findings are from static review of the provided source.
- Timing side-channels (the non-constant-time PIN-hash comparison) could not be measured; the exploitability of byte-at-a-time recovery within the 8-retry window is asserted from code shape, not observed.
- Real flash power-loss behavior (the non-atomic erase->program window, torn-write header states, and the blocked-retry-reset interaction) was not reproduced; the master-key-loss and brute-force-reset claims rest on reading write_sector/CredStore::load, not on glitching a device.
- Dual-core races (core-0 flash ops vs core-1 XIP fetch, and the missing acquire/release barrier on the signature handoff) are inherently nondeterministic and could not be triggered; severity is inferred from the RP2350 ROM/HAL documentation and the absence of multicore_lockout / DMB, with the Rust flash-vs-XIP instance left unconfirmed.
- The C stack-overflow exploitability beyond crash/DoS (whether it reaches code execution) was not validated -- no exploit was built, and stack layout / return-address adjacency on the specific toolchain were not confirmed.
- USB enumeration behavior (the XIAO GP23 warm-reset glitch, LCD-init panic halting before USB bring-up, single-rx_frame back-pressure) was not observed on hardware; impact is reasoned from the HAL and main-loop structure.
- TRNG entropy quality (SAMPLE_CNT1 tradeoff, health-test latch-off behavior) could not be measured; the AUTOCORR/CRNGT/VN failure modes are taken from the PAC register documentation.
- Several findings depend on exact line content that was not re-read when this record was compiled (e.g. the precise option-map parsing absence, getInfo key set, and credProtect suppression condition); those were graded conservatively, and a line-level re-read against the current tree is warranted before fixing.
- Test coverage is itself a gap: the Rust firmware parity base has zero unit tests and credProtect has no test in either port, so behaviors asserted as correct (credentialID round-trip, PIN key derivation, error-code discipline, credProtect gating) are unverified by the project's own harness.
- The vendored crypto crates (ML-DSA lowmemory, openssl-mini ML-DSA/EC) were treated as black boxes for correctness of the primitives themselves; only their integration (buffer sizing, randomizer, nonce source, return-value handling) was reviewed. FIPS 204 / RFC 6979 conformance of the underlying implementations was not independently verified.
- Commit-message and full-repo provenance audit was not performed exhaustively; only the source/comment references found in the review were consolidated.

---

## Executive summary

The real risk concentrates in two places: (1) the C port's PIN/CTAP decrypt paths, which contain unauthenticated, remotely-reachable stack buffer overflows (pin_decrypt and the GetAssertion hmac-secret salt path write attacker-controlled, length-unbounded plaintext into fixed 64/80-byte stack buffers before any MAC check) -- these are critical, memory-unsafe, and the single most dangerous cluster in scope; and (2) flash persistence on both ports, where a non-atomic single-sector erase/program with no journaling can wipe the device master keys on a routine login power-glitch, a blocked PIN counter is reset to full on reboot (defeating the only brute-force defence), and core-0 flash ops do not lock out core-1 (XIP-off window can fault the signing core). The Rust port is generally the stronger, spec-correct base but has its own high-severity issues: a UV/credProtect spoof when no PIN is set, an unbounded Vec::with_capacity heap-exhaustion DoS in the CBOR decoder, no CTAP HID channel arbitration (any second channel frame corrupts an in-flight transaction), non-constant-time PIN-hash comparison, and a TRNG driver that ignores hardware health-test bits (silent weak entropy or permanent hang). The C port additionally has a functional showstopper: hybrid MakeCredential always fails because the hybrid_sign staging buffer (640 B) is far too small for the ~2 KB ML-DSA public key in attested authData, so the flagship PQC registration path is non-functional on that port. Cross-cutting themes are constant-time discipline, the 0x33-vs-0x36 PIN error-code discipline, flash atomicity/multicore safety, integer-overflow hardening on the 32-bit target, secret zeroization, and a pervasive clean-room provenance violation (shipped source and the designated clean-room host crate name external implementations). Coverage is static-only: no hardware timing, real flash power-loss, USB enumeration, or dual-core race could be exercised, and the Rust parity base has zero unit tests.

