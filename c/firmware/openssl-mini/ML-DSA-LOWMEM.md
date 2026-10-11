# ML-DSA low-memory deviations from upstream

`src/ml_dsa/` was vendored from OpenSSL 3.5.0-dev like the rest of this
directory, but unlike `src/sha256.c` or the BN/EC tree it is **no longer
byte-for-byte upstream**. The RP2350 has 520 KiB of SRAM total and the
level-87 signing path did not fit; the changes below cut the heap the
FIPS 204 core asks for. They are listed here so a future re-vendor can
replay them against a newer upstream drop instead of rediscovering them.

Every change is behaviour-preserving: the KAT suite in `test/test_mldsa.c`
cross-checks public keys and signatures byte-for-byte against
BouncyCastle for 3 parameter sets x 6 seeds x 4 message lengths, and it
passes unchanged before and after. Nothing here alters the FIPS 204
output.

Techniques follow BouncyCastle's `mldsa-lowmemory` Rust crate
(`crypto/mldsa-lowmemory/src/low_memory_helpers.rs`, `aux_functions.rs`),
which regenerates matrix rows and unpacks the private key and signature
at the point of use rather than materialising them. Two of its choices
are deliberately **not** adopted, both noted where they arise: it
discards and recomputes `w` for the hint pass (section 5), and it bails
out of the norm checks on the first failing component (section 5).

## The changes

| File | Change | Upstream shape |
|---|---|---|
| `ml_dsa_sample.c` | Split `ossl_ml_dsa_matrix_expand_A_elem()` out of `ossl_ml_dsa_matrix_expand_A()`; the latter now loops over the former | One nested loop writing through `poly++` |
| `ml_dsa_sample.c` | Split `ossl_ml_dsa_expand_S_poly()` out of `ossl_ml_dsa_vector_expand_S()`; the latter now loops over the former | One function filling both vectors |
| `ml_dsa_matrix.h` | `struct matrix_st` gains `rho` / `md_ctx` / `md`; new `matrix_init_stream()`; `matrix_mult_vector()` returns `int` | Struct is `{ POLY *m_poly; size_t k, l; }`, multiply returns `void` |
| `ml_dsa_matrix.c` | `ossl_ml_dsa_matrix_mult_vector()` gains a streaming path and returns 1/0; the materialised path is unchanged | Single path |
| `ml_dsa_matrix.h` | New `matrix_get_elem()` - returns element (i, j) whichever form the matrix is in | Callers indexed `m_poly` directly |
| `ml_dsa_ntt.c` | New `ossl_ml_dsa_poly_ntt_mult_add()` - fused multiply-accumulate | Caller built a `POLY product` then `poly_add()`d it |
| `ml_dsa_encoders.c` | New `ossl_ml_dsa_pk_hash_init()` / `ossl_ml_dsa_pk_hash_poly()` - absorb the pkEncode byte stream a polynomial at a time as t1 is produced | tr is computed as `H(key->pub_encoding)` |
| `ml_dsa_encoders.c` | New `ossl_ml_dsa_priv_pack_alloc()` / `ossl_ml_dsa_priv_pack_poly()` / `ossl_ml_dsa_priv_unpack_poly()` - the packed private key one polynomial at a time in either direction, over a shared `priv_packed_slot()` | - |
| `ml_dsa_encoders.c` | `ossl_ml_dsa_sig_encode()` replaced by `ossl_ml_dsa_sig_z_packed_len()` + `ossl_ml_dsa_sig_encode_z()` + `ossl_ml_dsa_sig_make_hint()`, which write into the caller's signature buffer; `hint_bits_encode()` folded into the last of those | One pass over an assembled `ML_DSA_SIG` |
| `ml_dsa_encoders.c` | `ossl_ml_dsa_sig_decode()` replaced by `ossl_ml_dsa_sig_decode_z()` + `ossl_ml_dsa_sig_decode_h_row()`; `hint_bits_decode()` folded into the latter | One pass filling a whole `ML_DSA_SIG` |
| `ml_dsa_encoders.c` | `ossl_ml_dsa_w1_encode()` replaced by `ossl_ml_dsa_w1_encode_poly()` | Vector at a time |
| `ml_dsa_poly.h` | `poly_make_hint()` dropped - MakeHint is now fused into HintBitPack in `ml_dsa_encoders.c` | MakeHint wrote a polynomial of 0/1 words |
| `ml_dsa_vector.h` | `vector_low_bits_max()` and `vector_make_hint()` dropped - both loop bodies moved into `ml_dsa_sign.c` | - |
| `ml_dsa_sign.h` | Deleted - `ML_DSA_SIG` existed only to carry (z, hint, c_tilde) between the sign/verify loops and sigEncode/sigDecode, and neither side needs it now | `struct ml_dsa_sig_st` |
| `ml_dsa_key.c` | `keygen_internal()` takes a `sign_only` flag and dispatches to `keygen_full()` (the upstream body) or `keygen_sign_only()`; new `ossl_ml_dsa_generate_key_for_sign()`; `public_from_private()` streams A and now reports failure | One keygen mode; `public_from_private()` returned 1 unconditionally |
| `ml_dsa_key.c` | Every block that has held t or t0 is released cleansed: `public_from_private()`, `ossl_ml_dsa_key_public_from_private()`, `ossl_ml_dsa_key_pairwise_check()` and `keygen_sign_only()` | `public_from_private()` zeroed only `s1_ntt` and `OPENSSL_free()`d the block t was still in; the other two freed t0 uncleansed. Upstream bug, not one of ours |
| `ml_dsa_sign.c` | Verify streams A; sign streams A under `PQF_MLDSA_LOWMEM`; `num_polys_sig_k = 2*k` corrected to `k + l`; verify's unused `num_polys_l` dropped; private-key presence test reads `s1.poly` | Both materialise A; two over-allocations; test read `priv_encoding` |
| `ml_dsa_sign.c` | Both loops run a polynomial at a time (sections 5 and 7); new `sign_priv_poly_ntt()`; verify checks `sig_enc_len` itself | Whole-vector loop bodies; sigDecode checked the length implicitly |
| `ml_dsa_key.h` | `struct ml_dsa_key_st` gains `s_packed`, the bit-packed s1/s2/t0 a sign-only key carries instead of the three vectors | Struct holds only the unpacked `s1` / `s2` / `t0` |
| `include/crypto/ml_dsa.h` | Declares `ossl_ml_dsa_generate_key_for_sign()` | - |

### 1. A is expanded a row at a time

ExpandA (FIPS 204 Algorithm 32) samples every element of the `k x l`
matrix independently from `rho || j || i`, and the only consumer,
`ossl_ml_dsa_matrix_mult_vector()`, already walked it strictly row by
row. So the matrix can be re-derived element by element as the multiply
reaches it, holding one polynomial instead of `k * l`: 15/29/55 KiB saved
at ML-DSA-44/65/87.

Key generation and verification multiply by A exactly once, so they
stream unconditionally - it costs them nothing measurable. Signing
multiplies once per rejection iteration (4-5 expected), so there
streaming re-runs ExpandA per iteration and costs about 1.3x on the
ML-DSA arithmetic. That case is under the `PQF_MLDSA_LOWMEM` build
option; see below.

### 2. Fused multiply-accumulate

`ossl_ml_dsa_matrix_mult_vector()` built a whole 1 KiB `POLY product` on
the stack for each `(i, j)` and then added it in. Accumulating
`reduce_montgomery(a * s)` straight into the destination coefficient is
arithmetically identical - both reduce the product to `0..q-1` and then
`reduce_once()` the sum - and drops the frame from 1072 to 40 bytes on
Cortex-M33, plus one read/write pass over 1 KiB per matrix element.

### 3. Signing does not build the encoded key pair

`pqf_mldsa_sign()` re-derives the key from the 32-byte seed in the
credential ID on every signature. Upstream `keygen_internal()` always
finishes with `pk_encode()` + `sk_encode()`, so the encoded public and
private keys stayed resident for the whole signature even though
ML-DSA.Sign reads neither: it needs only rho, tr, K, s1, s2 and t0.

`ossl_ml_dsa_generate_key_for_sign()` stops after the values signing
uses. `tr` still has to be the hash of the encoded public key, so
`ossl_ml_dsa_pk_hash_init()` / `ossl_ml_dsa_pk_hash_poly()` feed pkEncode's
byte stream into SHAKE-256 one polynomial at a time (320 bytes of stack)
instead of allocating the `pk_len` buffer. Together with dropping `t1` - it
only feeds the public key encoding - that is 15,680 bytes at ML-DSA-87.

The resulting key can sign but cannot be exported, duplicated or used to
verify. `ossl_ml_dsa_generate_key()` is unchanged and still produces a
full key; `pqf_mldsa_pub_from_seed()` uses it.

Two consequential fixes came with this:

- `ml_dsa_sign.c` tested `ossl_ml_dsa_key_get_priv(priv) == NULL` as a
  presence flag. It now tests `priv->s1.poly == NULL`, which is what
  signing actually reads. This also closes an upstream hole: a prekey
  staged through `ossl_ml_dsa_set_prekey()` with an `sk` but never
  expanded has a non-NULL `priv_encoding` and a NULL `s1`, and the old
  test would have let it through into a NULL dereference.
- `public_from_private()` returned 1 even when `matrix_expand_A()`
  failed, silently yielding garbage `t1`/`t0`. It now returns 0. Every
  caller already treated 0 as failure.

### 4. Dead slack in the signature allocation

Two over-allocations, both upstream:

- `ml_dsa_sign_internal()` reserved `num_polys_sig_k = 2 * k`
  polynomials for the signature but the `ML_DSA_SIG` it built only used
  `k + l` (`hint` was k, `z` is l). Corrected to `k + l`: no change at
  ML-DSA-44 where k == l, 1 KiB at 65 and 87. Section 6 later removed the
  reservation entirely.
- `ml_dsa_verify_internal()` reserved `num_polys_l = l` and never used
  it. Its consumers were `c_ntt` (1), the A scratch (1), `sig` (k + l),
  `az_ntt` (k) and `ct1_ntt` (k) -- `num_polys_k = 2 * k` already covers
  the last two. Dropped: 4/5/7 KiB at 44/65/87.

### 5. The signing loop runs a polynomial at a time

Upstream's rejection loop holds seven vectors -- `y`, `cs1` (which also
serves as `NTT(y)`), `cs2`, `w`, `s1_ntt`, `s2_ntt`, `t0_ntt` -- plus two
scratch polynomials, giving an allocation of `2 + 3l + 4k` polynomials
before A. Only `y` and `w` are genuinely live across a whole pass; the
rest are consumed in the same order they are produced.

**The matrix multiply is inverted to column-outer / row-inner.**
`matrix_mult_vector()` walks A row by row and so needs all of `NTT(y)`
at once. Accumulating column by column instead --

    zero w
    for col in 0..l:  ynt = NTT(y[col])
                      for row in 0..k:  w[row] += A[row][col] * ynt

-- runs exactly the same `l` transforms and `k * l` ExpandA expansions,
so it adds no recomputation, but `NTT(y)` collapses to one scratch
polynomial. ExpandA samples each element from `rho || j || i`
independently, so a streaming A does not care that it is now reached in
column order; `matrix_get_elem()` hides which form the matrix is in.

**`w` is deliberately kept as a k polynomial vector.** BouncyCastle
discards `w` and recomputes it for the hint pass, which is where most of
its 2.2-2.9x signing penalty comes from. Keeping it costs k polynomials
and saves a second `A * NTT(y)`.

**s1, s2, t0, cs1, cs2 and ct0 become scratch.** Each is derived where
it is consumed: `sign_priv_poly_ntt()` decodes one polynomial out of
`key->s_packed` (see section 3) and transforms it, and the product is
formed in place. The r0 pass and the hint pass both read `w[row]` and
`c * s2[row]`, so they are fused into one row loop -- that is what lets
`c * s2` be per-row rather than a vector.

The allocation goes from `2 + 3l + 4k` polynomials plus a `k * 32` byte
hint bitmap to `3 + k + l` and no bitmap -- the live set is `y` (l) +
`w` (k) + `c_ntt` + two scratch. With the A element added (1 streaming,
`k * l` materialised) that is 27/44/19 polynomials at 44/65/87 against
46/71/56, the asymmetry being that only 87 streams by default.

The four rejection bounds are still accumulated over whole vectors and
weighed by a single branchless test. BouncyCastle bails on the first
failing component (its T10), which leaks *which* one failed; that is not
adopted. Fusing the two passes in fact removes a branch point -- upstream
tested `z`/`r0` before computing the hint, and there is now one combined
test of all four -- so the leak is strictly coarser than before, never
finer. It costs the ct0 work on rejected attempts, which upstream
skipped; that is the bulk of the CPU figure below.

### 6. The signature is packed into the caller's buffer

Upstream builds `c_tilde`, an l polynomial `z` and a hint bitmap, then
calls sigEncode to pack all three into `out_sig`. Every field has a
fixed offset, so each is instead written where it belongs as it is
produced:

- `c_tilde` is squeezed straight into `out_sig`.
- `z[col]` is bit-packed by `ossl_ml_dsa_sig_encode_z()`, which points a
  `WPACKET` at that column's slot -- the bit packing itself is still the
  one copy in `poly_encode_signed_two_to_power_17/19()`.
- HintBitPack encodes the set coefficient indices, so MakeHint can write
  them directly. `ossl_ml_dsa_sig_make_hint()` does both and returns the
  running total, which removes the `k * 32` byte bitmap and the second
  pass over it.

`out_sig` is zeroed at the top of every rejection iteration. This is
required, not tidiness: the hint only writes the index slots it fills, so
a rejected attempt with more hint bits than its successor would leave
stale indices behind. A rejected attempt can also exceed omega bits;
index writes are clamped to the omega region so they cannot run into the
run totals, while the returned count stays exact so the existing
branchless `omega < h_ones` test still rejects. A failure return now
cleanses `out_sig`, since attempts write through it.

### 7. Verification decodes the signature a row at a time

`ossl_ml_dsa_sig_decode()` materialised `z` (l) and the hint (k * 32)
up front. Verification has no rejection loop, so the same column-outer
order as section 5 works directly: each `z` column is decoded into one
scratch polynomial, weighed into the `||z||inf` bound, transformed and
multiplied into every row of `w_approx`. Then one row loop forms
`c * t1[row] * 2^d`, subtracts it, inverts the transform, decodes that
row's hint into a 32-byte stack bitmap, applies UseHint and encodes the
row of w1. The allocation goes from `1 + l + 2k` polynomials plus the
`k * 32` byte bitmap to `2 + k`, both plus the one A element: 7/9/11
polynomials at 44/65/87 against 14/19/25.

Two details from BouncyCastle's `unpack_h_row` are load-bearing and are
kept:

- The row's run of indices starts at `sig[pos + omega + row - 1]` rather
  than being found by walking the earlier rows. The encoding stores those
  running totals, so a row is independently addressable.
- The check that the unused index bytes are zero needs the last row's
  running total, so it is deferred to row `k - 1`.

Dropping either weakens malformed-signature rejection, and both are
covered: a differential run over 180,822 mutations of a valid signature
at all three parameter sets gives verdicts identical to upstream, and
1.2 million crafted hint encodings -- run totals above omega, run totals
going backwards, repeated and decreasing indices inside a row, nonzero
padding, and uniform random -- make the per-row decoder agree with
upstream's whole-vector `hint_bits_decode()` on both the accept/reject
flag and the decoded bitmap. Removing either detail breaks that
agreement.

Verification is stripped from the device image by `--gc-sections`, so
this is about host memory and keeping the two sides symmetric, not device
RAM.

### 8. Key generation packs s1, s2 and t0 as it produces them

After section 5 the largest single allocation at ML-DSA-87 was no longer
in signing: it was the `(l + 2k)` polynomial block
`ossl_ml_dsa_key_priv_alloc()` reserves for the unpacked s1, s2 and t0,
23,552 bytes, and `pqf_mldsa_sign()` re-derives the key from its 32-byte
seed on every signature. Section 3 packed that block down to
`s_packed` - but only *after* materialising it, so the peak was unmoved.

`keygen_sign_only()` walks Algorithm 6 producing one polynomial at a time
and writes each into its slot in `s_packed` as it appears, so the unpacked
form is never assembled at either end of the key's life:

- **ExpandS.** Each polynomial of `s1 || s2` is an independent rejection
  sample from `p' || index`, exactly as each element of A is, so
  `ossl_ml_dsa_expand_S_poly()` splits out of
  `ossl_ml_dsa_vector_expand_S()` the same way
  `ossl_ml_dsa_matrix_expand_A_elem()` did in section 1. Each sample is
  packed straight out of the scratch polynomial it lands in.
- **t = A\*NTT(s1) + s2** is accumulated column by column, unpacking and
  transforming one column of s1 at a time - the same column-outer /
  row-inner inversion section 5 applied to the signing loop, and for the
  same reason: it runs the same `l` transforms and `k * l` expansions, so
  it adds no recomputation, but `NTT(s1)` collapses to one scratch
  polynomial. `t` stays as `k` polynomials; it is the one value here that
  is live across a whole pass. Reducing it further would mean an
  `NTT(s1[col])` per row, `k * l` transforms instead of `l`.
- **Power2Round** is applied a row at a time: that row of t0 goes to its
  slot in `s_packed` and that row of t1 is absorbed into
  `tr = H(pkEncode(rho, t1))` and dropped, which is what splitting
  `ossl_ml_dsa_pk_hash()` into an init and a per-polynomial update is for.

The unpacked storage goes from `2l + 4k + 1` polynomials to `k + 2`. Three
blocks were live at once at the old peak: the `(l + 2k)` private block,
`t1` (`k`), and `public_from_private()`'s own `(k + l + 1)`. At ML-DSA-87
that is 47 polynomials, 48,128 bytes, and the live set at the instant the
old peak was reached was exactly those three blocks: 23,552 + 16,384 +
8,192. What replaces them is `t` (`k`) plus two scratch blocks, one for
whichever private polynomial is in flight and one for the A element, which
doubles as the t0 row once the multiply is done. The scratch pair is a
separate allocation from `t` so that the largest block asked for is `k`
polynomials, not `k + 2`.

`ossl_ml_dsa_generate_key()` is untouched: `keygen_full()` is the upstream
body verbatim, still materialising s1, s2, t1 and t0 and encoding them,
because a key that has to be exported needs them anyway.
`pqf_mldsa_pub_from_seed()` uses it and its heap figures do not move.

The packing is fixed-width bit manipulation over every coefficient - the
same `poly_encode_signed_2/4` and `poly_encode_signed_two_to_power_12` the
whole-vector skEncode uses - so it does not branch on the secret it is
packing. It does point a `WPACKET` at one polynomial's slot rather than at
a whole vector's, so the 40-byte sub-packet allocations in a sign-only key
generation go from 9 to 31 at ML-DSA-87 (5 to 16 at 44, 7 to 23 at 65).
Each is freed before the next is taken - measured maximum concurrency is
one, at every parameter set, before and after - so neither the peak nor the
largest request moves.

`keygen_sign_only()` releases both of its blocks cleansed: `t0` is
recoverable from `t` because t = t1\*2^d + t0, so `t` is a private value in
its own right, and that is true on the success path as well as the error
path. The same reasoning applies to `public_from_private()`, which upstream
frees uncleansed; see the change table.

The three sources section 8 edits - `ml_dsa_key.c`, `ml_dsa_encoders.c`,
`ml_dsa_sample.c` - introduce no new compiler warnings. Each still emits
the one pre-existing `-Wextra` warning `ml_dsa_vector.h` has, an unused
`rho_prime_len` parameter in `vector_expand_mask()`.

Beyond the KAT suite, the equivalence is checked directly: for 24 seeds at
each of the three parameter sets, `tr`, `rho`, `K` and the whole
`s_packed` block a sign-only key generation produces are byte-identical to
`tr`, `rho`, `K` and the tail of `skEncode()` from a full key generation
on the same seed.

## Build option

`PQF_MLDSA_LOWMEM` (CMake cache variable, also passed to the RISC-V
core-1 blob by `core1-riscv-blob/build_blob.sh`) selects whether the
*signing loop* streams A:

| Value | Behaviour |
|---|---|
| 0 | Never stream in the signing loop - materialise A once (fastest signing) |
| 1 | Always stream (smallest heap) |
| 2 | Stream only for parameter sets with `k * l >= 32`, i.e. ML-DSA-87 (**default**) |

Key generation and verification always stream regardless; there is no
trade to make there.

The default streams at 87 and not at 44/65 because 87 is the only level
that carries a `PQF_SIGN_ARENA`. That arena exists to serve one large
contiguous allocation from `ml_dsa_sign.c`, and it is what forces
`PQF_COPY_TO_RAM=OFF` on the Arm/87 build. At 44 and 65 there is no arena
and no reason to pay the CPU.

Measured size of that one allocation -- `w1_encoded` plus
`3 + k + l + (streaming ? 1 : k * l)` polynomials:

| Level | `PQF_MLDSA_LOWMEM=0` | `=1` | `=2` (default) |
|---|---|---|---|
| 44 | 28,416 | 13,056 | 28,416 |
| 65 | 45,824 | 16,128 | 45,824 |
| 87 | 76,800 | 20,480 | 20,480 |

Streaming now takes the level-87 signing blob from 76,800 to 20,480 bytes
rather than from 137,216 to 58,624.

Between sections 5 and 8 that 20,480 was not the largest thing signing
asked for -- the `l + 2k` polynomial block key generation allocated for the
unpacked s1/s2/t0 was 23,552 at 87, and signing re-derives the key from
its seed every time -- so `PQF_SIGN_ARENA_BYTES` and the level-87
`PQF_COPY_TO_RAM` default were briefly gated by key generation rather than
by the signing loop. Section 8 takes that block to `k` polynomials, 8,192
bytes at 87, which is below the streaming signing blob at every parameter
set, so the table above is once again the whole story for the largest
allocation. These are host measurements; re-measure on the device before
resizing the arena.

## Measured effect

Host measurements (`cc -O2 -std=gnu11`, arm64 macOS), heap high-water
through a malloc interposer that also records the largest single
request. Baseline column is a pristine `git archive` of the pre-change
tree measured with the same harness and the same fixed seed and message,
so the two columns are directly comparable:

| Level | Op | Peak before | Peak after | Largest before | Largest after |
|---|---|---|---|---|---|
| 44 | pub_from_seed | 41,216 | 25,864 | 24,576 | 12,288 |
| 44 | sign | 79,688 | 31,152 | 59,136 | 28,416 |
| 44 | verify | 43,048 | 12,336 | 38,656 | 7,936 |
| 65 | pub_from_seed | 65,792 | 36,104 | 41,984 | 17,408 |
| 65 | sign | 120,712 | 50,032 | 90,880 | 45,824 |
| 65 | verify | 67,624 | 16,432 | 61,184 | 9,984 |
| 87 | pub_from_seed | 104,704 | 48,392 | 72,704 | 23,552 |
| 87 | sign | 177,768 | **25,552** | 138,240 | **20,480** |
| 87 | verify | 106,792 | 20,784 | 98,304 | 12,288 |

The "largest single request" column matters as much as the peak: it is
what an allocator has to find contiguously, and it is what a dedicated
arena exists to guarantee against newlib fragmentation. At ML-DSA-87 it
has gone from 138,240 bytes to 20,480, which is the signing loop's own
streaming block -- the largest thing key generation now asks for is 8,192.

The `pub_from_seed` rows are the full key generation, which section 8
deliberately leaves alone; they are what a key that has to be exported
costs. Signing does not use that path.

Sections 5 to 8 landed after the rest, so their own contribution is
listed separately. The verify rows move only at section 7, the sign rows
at 5, 6 and 8, so the columns below are the peak after each:

| Level | Op | Sections 1-4 | + 5 | + 6 | + 7 | + 8 |
|---|---|---|---|---|---|---|
| 44 | sign | 50,736 | 31,280 | 31,152 | 31,152 | 31,152 |
| 65 | sign | 77,872 | 50,224 | 50,032 | 50,032 | 50,032 |
| 87 | sign | 63,696 | 48,392 | 48,392 | 48,392 | 25,552 |
| 44 | verify | 19,632 | 19,632 | 19,632 | 12,336 | 12,336 |
| 65 | verify | 26,864 | 26,864 | 26,864 | 16,432 | 16,432 |
| 87 | verify | 35,376 | 35,376 | 35,376 | 20,784 | 20,784 |

Between sections 5 and 7 the level-87 sign peak stopped falling at 48,392
even though its blob kept shrinking, because from there it was pinned by
key generation -- it was exactly the `pub_from_seed` peak. Section 8
unpins it. The 44 and 65 sign rows do not move, because at the default
`PQF_MLDSA_LOWMEM=2` those levels do not stream A and their peak is set by
the 28,416 / 45,824 byte signing blob, not by key generation. With
`PQF_MLDSA_LOWMEM=1`, where every level streams and the signing blob is
small, section 8 shows at all three:

| Level | Op | Sections 1-7 | + 8 | Largest 1-7 | Largest + 8 |
|---|---|---|---|---|---|
| 44 | sign | 25,864 | 15,792 | 13,056 | 13,056 |
| 65 | sign | 36,104 | 20,336 | 17,408 | 16,128 |
| 87 | sign | 48,392 | 25,552 | 23,552 | 20,480 |

In that column every level's largest allocation is now the signing blob
from the build-option table, so key generation no longer sets the
contiguous requirement anywhere.

The two key generation modes measured on their own, without a signature
around them, which is section 8's effect in isolation:

| Level | Mode | Peak 1-7 | Peak + 8 | Largest 1-7 | Largest + 8 |
|---|---|---|---|---|---|
| 44 | sign-only | 25,864 | 8,880 | 12,288 | 4,096 |
| 65 | sign-only | 36,104 | 12,400 | 17,408 | 6,144 |
| 87 | sign-only | 48,392 | 15,312 | 23,552 | 8,192 |
| 44 | full | 25,864 | 25,864 | 12,288 | 12,288 |
| 65 | full | 36,104 | 36,104 | 17,408 | 17,408 |
| 87 | full | 48,392 | 48,392 | 23,552 | 23,552 |

The two modes were identical up to section 8 - `sign_only` packed the
private vectors and released them, but only after the unpacked block had
already set the peak. The 15,312 at 87 is `s_packed` 4,768 + `t` 8,192 +
two scratch polynomials 2,048, and the largest request is `t`; the balance
is the key object, the EVP context and one 40-byte WPACKET sub-packet, so
how much of it a figure carries depends on where the harness opens its
window.

CPU, same host build, median of three runs of 200 operations each
(`REPS=200`, one signature per distinct seed so the rejection-iteration
count is averaged over):

| Level | Op | Upstream | Sections 1-4 | All sections | vs upstream |
|---|---|---|---|---|---|
| 44 | pub_from_seed | 0.067 ms | 0.062 | 0.063 | 0.94x |
| 44 | sign | 0.390 ms | 0.388 | 0.537 | 1.38x |
| 44 | verify | 0.070 ms | 0.071 | 0.069 | 0.99x |
| 65 | pub_from_seed | 0.117 ms | 0.117 | 0.114 | 0.97x |
| 65 | sign | 0.615 ms | 0.606 | 0.824 | 1.34x |
| 65 | verify | 0.112 ms | 0.111 | 0.109 | 0.97x |
| 87 | pub_from_seed | 0.170 ms | 0.167 | 0.167 | 0.98x |
| 87 | sign | 0.789 ms | 1.011 | 1.243 | 1.58x |
| 87 | verify | 0.181 ms | 0.181 | 0.175 | 0.97x |

Signing is the only path that pays, and it pays twice. Streaming A costs
1.28x at 87 and nothing at 44/65, because the default policy only streams
at 87. Section 5 adds a further 1.23-1.38x everywhere: re-deriving s1, s2
and t0 per rejection iteration instead of once, and computing ct0 on
rejected attempts that used to skip it. Key generation and verification
are unchanged to within run-to-run noise.

Section 8's arithmetic is the same work in a different order - the same
`l + k` bounded samples, `l` transforms and `k * l` expansions - plus
`l + k` extra BitUnpack passes, one per column of s1 read back for the
multiply and one per row of s2 read back for the addition. That does not
separate from run-to-run drift on this host: measured as medians of three
runs of 200 operations, sign went 0.592 / 0.875 / 1.248 ms to 0.593 /
0.891 / 1.279 at 44 / 65 / 87, but verify - which section 8 does not touch
at all - moved 0.070 / 0.109 / 0.176 to 0.071 / 0.113 / 0.179 in the same
runs. Take the verify row as the noise floor: the real cost is at or below
1%.

Hybrid (ECDSA + ML-DSA) arena high-water, measured through
`core1-riscv-blob/blob_alloc.c` - the allocator the signing path actually
runs on (the ECDSA half draws a random nonce, so these move by a few
tens of bytes run to run):

| Level | `hybrid_public` before | after | `hybrid_sign` before | after |
|---|---|---|---|---|
| 44 | 51,376 | 36,192 | 97,120 | 94,008 |
| 65 | 76,152 | 46,464 | 138,192 | 131,320 |
| 87 | 114,840 | 58,720 | 195,784 | 131,264 |

TREAT THIS TABLE AS STALE. Its "after" column predates sections 5 to 7
and was never reproduced even for sections 1-4: a later attempt could not
isolate the sign from `test_blob_alloc`'s own stress phase, which sets a
147 KiB high-water before any crypto runs. The `hybrid_sign` figures also
sit well above the ML-DSA-only peaks in the table above (48,392 at 87),
which the ECDSA half does not plausibly account for. The ML-DSA-only
numbers above are the ones to trust. Re-measure this table properly
before sizing `PQF_SIGN_ARENA_BYTES` down or flipping the level-87
`PQF_COPY_TO_RAM` default.

Cortex-M33 static stack (`arm-none-eabi-gcc -O2 -mcpu=cortex-m33 -mthumb
-ffunction-sections -fdata-sections -fstack-usage`, summed along the
deepest call chain, including the SHAKE layer in `sha3.c` /
`keccak1600.c` and excluding the EVP dispatch layer in `pqf_evp.c`). All
three columns were measured with that one command, so they are directly
comparable:

| Path | Before | Sections 1-4 | After | Deepest chain after |
|---|---|---|---|---|
| sign | 2,568 | 1,232 | **1,024** | `sign` 384 + `expand_A_elem` 232 + `sha3_squeeze` 40 + `SHA3_squeeze` 248 + `Round` 120 |
| verify | 2,432 | 1,064 | **936** | `verify` 296 + `expand_A_elem` 232 + `sha3_squeeze` 40 + `SHA3_squeeze` 248 + `Round` 120 |
| keygen | 1,360 | 1,008 | **1,016** | `generate_key` 240 + `pk_hash_poly` 376 + `sha3_update` 40 + `SHA3_absorb` 240 + `Round` 120 |

Before, all three were dominated by two frames that no longer exist:
`ossl_ml_dsa_matrix_mult_vector`'s 1072-byte on-stack `POLY product`
(the accumulation is fused, and signing and verification no longer call
it at all) and `ossl_ml_dsa_poly_expand_mask`'s 664-byte squeeze buffer
(now 40 bytes, the squeeze is incremental). `ossl_ml_dsa_sign` itself
went from 1496 bytes to 384 - and that 384 now includes
`ml_dsa_sign_internal`, which the compiler inlines back into it once the
frame is small enough; the same is true of `verify` at 296. Sign and
verify are untouched by section 8.

Key generation is the only path section 8 moves, and it moves by 8 bytes:
`keygen_internal()` and both of its two halves inline into
`generate_key()`, which is why the chain lost a level and gained the 208
bytes that used to be `keygen_internal`'s. The deepest frame is still the
320-byte pkEncode buffer, now in `ossl_ml_dsa_pk_hash_poly()`; the
`ossl_ml_dsa_expand_S_poly()` branch of the same tree is 240 + 256 + 40 +
240 + 120 = 896.

`.text` for the ml_dsa group (`arm-none-eabi-size -t ml_dsa_*.o`, same
flags, `arm-none-eabi-gcc 15.2.Rel1`). All four rows are one run of one
script over the four trees, so they are directly comparable; an earlier
toolchain drop read the same trees a few tens of bytes differently, so
re-measure the whole column rather than adding a row to it:

Three trees, measured in one session by one command
(`arm-none-eabi-gcc -O2 -mcpu=cortex-m33 -mthumb -ffunction-sections
-fdata-sections -DPQF_HYBRID_VARIANT=87` over `src/ml_dsa/*.c`, then
`arm-none-eabi-size -t`, arm gcc 15.2.Rel1):

| Tree | ml_dsa group `.text` | vs upstream |
|---|---|---|
| Upstream (pristine) | 17,578 | - |
| Sections 1-7 | 17,995 | +417 |
| Sections 1-8, plus the cleanse fix below | 18,727 | +1,149 |

Earlier revisions of this table carried a fourth column and per-object
attributions that could not be reproduced on a second toolchain, and one
row attributed +63 bytes to cleansing code that the compiler was in fact
deleting (see below). Rather than explain the drift, the column was
re-measured from scratch; do the same if you change any of these
sections, and quote a whole column from one run rather than adding a row
to someone else's.

Part of the last row is not this section at all: making
`OPENSSL_cleanse()` actually work (`include/openssl/crypto.h`) turns five
deleted `memset` calls into emitted volatile store loops, which is +284
bytes in `ml_dsa_key.o` alone. That was a real bug, not a cost: compiled
`-O2 -mcpu=cortex-m33`, a function that allocated a buffer, wrote to it
and then `memset`+`free`d it reduced to a single `bx lr` - the store, the
`memset` and the `free` all eliminated. Every cleanse in this tree was a
no-op in the shipped firmware, leaving ML-DSA private vectors in freed
heap. Zeroing stores in `ml_dsa_key.o` went from 2 to 13 once the
primitive wrote through a volatile pointer.

`.data` and `.bss` are zero in every ml_dsa object in every tree.

## Re-vendoring

If `src/ml_dsa/` is refreshed from a newer upstream:

1. Take the new upstream tree verbatim.
2. Re-apply the file changes in the table above. Sections 2 and 4 are
   small and local. Section 1 touches the `MATRIX` type, so check whether
   upstream has changed `struct matrix_st`; with section 5 in place the
   streaming path is reached in column order via `matrix_get_elem()`, so
   any *new* upstream consumer of A must also be checked to be
   order-agnostic.
3. Sections 3 and 8 add a second keygen mode rather than modifying the
   existing one - `keygen_full()` is upstream's `keygen_internal()` body
   verbatim - so they should port cleanly unless upstream restructures
   `keygen_internal()` itself. `ossl_ml_dsa_key_priv_alloc()` and
   `public_from_private()` are only reached by the full mode. Re-apply the
   cleansing in the table above: it is not a low-memory change and a newer
   upstream will still be freeing t and t0 uncleansed unless it has been
   reported and fixed there.
4. Sections 5 to 7 rewrite the two loop bodies in `ml_dsa_sign.c` almost
   completely, and delete `ossl_ml_dsa_sig_encode()`,
   `ossl_ml_dsa_sig_decode()`, `ossl_ml_dsa_w1_encode()`,
   `poly_make_hint()` and `ml_dsa_sign.h`. Take the versions here rather
   than trying to merge: the offsets they encode to are fixed by FIPS 204,
   so the only thing to re-check against a new upstream is whether the
   per-polynomial encoders they call have changed signature.
5. Run `test/` - it must report `0 failure(s)` for all six groups, and
   `../test/` all eleven. The ML-DSA vectors are the oracle; they are
   independent of this implementation.
6. If section 7 is re-derived rather than taken as is, re-check the two
   malformed-signature details it calls out. The KAT suite does not cover
   them: `verify rejects altered signature` flips one byte, which the
   `c_tilde` comparison catches on its own.
7. If section 8 is re-derived, re-check that `ossl_ml_dsa_expand_S_poly()`
   builds the same `p' || IntegerToBytes(index, 2)` seed upstream's
   ExpandS loop does, and that the sign-only and full modes still agree
   byte-for-byte on `tr` and on the packed private block against
   `skEncode()`'s tail. The KAT suite catches a disagreement in either
   through the signature, but not which of the two is wrong.
