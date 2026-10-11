//! This crate defines the core traits and types used by the rest of the bc-rust.test library.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

// The allocating one-shot APIs (`Hash::hash`, `MAC::mac`, `KDF::derive_key`,
// ...) return `Vec` / `Box`, so `no_std` here means `no_std + alloc` rather
// than allocation-free. Upstream's longer-term intent is to drop `Vec` in
// favour of compile-time array sizing; until then, embedded consumers pair
// this with a global allocator and use the `*_out` variants on hot paths.
extern crate alloc;
// The in-crate unit tests print; they need std back under `cargo test`.
#[cfg(test)]
extern crate std;

pub mod errors;
pub mod key_material;
pub mod suspendable_state;
pub mod traits;
