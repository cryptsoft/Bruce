// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! CTAPHID transport -- opening a FIDO HID device, the INIT
//! handshake, framed read/write of arbitrary-length messages.
//!
//! Specs:
//!
//! - FIDO U2F HID v1.2 sec. 6 -- packet structure, INIT handshake,
//!   error codes.
//! - CTAP 2.1 sec. 11.2.9 -- CBOR / CANCEL / KEEPALIVE additions on top
//!   of the U2F HID base.
//!
//! # Layering
//!
//! `pqf-ctaphid` uses [`hidapi`] for the per-OS HID plumbing
//! (IOKit on macOS, hidraw on Linux, WinUSB on Windows). Above the
//! 64-byte HID report layer, everything is in-tree: frame
//! construction in [`frame`], message reassembly in this module,
//! and the application-layer CBOR commands in [`crate::ctap2`].
//!
//! # Public surface
//!
//! - [`enumerate`] -- list FIDO HID devices currently attached.
//! - [`DeviceInfo`] -- what `enumerate` returns. Carries the
//!   `hidapi` path you pass to [`Device::open`] plus enough product
//!   metadata to render a "pick a key" UI.
//! - [`Device`] -- an opened, INIT-completed handle. Methods on
//!   `Device` are the low-level transport: [`Device::send_msg`],
//!   [`Device::recv_msg`], plus convenience wrappers
//!   ([`Device::ping`], [`Device::wink`], [`Device::cancel`]).
//! - [`Capabilities`] -- bitmask returned by INIT; tells you whether
//!   the device supports CBOR (CTAP2), WINK, and whether
//!   `CTAPHID_MSG` (U2F) is *unsupported* (the NMSG bit).
//! - [`Stats`] -- transport counters (bytes moved, KEEPALIVE frames
//!   seen) accumulated per-`Device`, for callers that want to
//!   measure a transaction rather than just perform it.
//!
//! Higher-level CTAP 2.1 commands (`getInfo`, `makeCredential`,
//! ...) live in [`crate::ctap2`] and consume a `Device` via
//! [`Device::send_msg`] / [`Device::recv_msg`].

use std::cell::Cell;
use std::sync::mpsc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use rand::rngs::OsRng;

mod error;
mod frame;

pub use error::{hid_err, Error};
pub use frame::{Cmd, BROADCAST_CID, INIT_PAYLOAD_CAP, MAX_MSG_LEN, REPORT_LEN};

/// FIDO HID usage page -- devices that advertise this usage page on
/// their HID descriptor are CTAP-speaking authenticators.
/// FIDO U2F HID v1.2 sec. 3.
pub const FIDO_USAGE_PAGE: u16 = 0xf1d0;

/// FIDO HID usage code paired with [`FIDO_USAGE_PAGE`].
pub const FIDO_USAGE: u16 = 0x0001;

/// Default per-frame read timeout, in milliseconds.
///
/// CTAP commands that legitimately take seconds (large-blob writes,
/// on-device key generation, ML-DSA signing) issue `CTAPHID_KEEPALIVE`
/// frames every ~100 ms, so we never block for longer than that
/// between frames in steady state. The timeout below catches the
/// disconnected-mid-conversation case.
pub const READ_TIMEOUT_MS: i32 = 5000;

/// Largest byte count a single [`Cmd::Rng`] transaction may request --
/// mirrors `CTAPHID_RNG_MAX` in the firmware. [`Device::rng`] splits
/// larger reads across multiple transactions.
pub const RNG_MAX_XACT: usize = 1024;

/// Reboot target for [`Device::reboot`]. The discriminant is the mode
/// byte sent on the wire (matches the firmware's `CTAPHID_REBOOT_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RebootMode {
    /// Warm reboot back into the firmware (re-enumerates unchanged).
    Warm = 0x00,
    /// Reboot into the RP2350 USB bootloader (mass storage / DFU),
    /// e.g. for reflashing with `picotool`.
    Bootsel = 0x01,
}

// ---------- Enumeration ----------

/// Snapshot of an attached FIDO HID device. Returned by [`enumerate`].
///
/// The `path` field is the hidapi-internal device path and is what
/// you pass to [`Device::open`]. It's an opaque string and may not
/// be stable across replug.
#[derive(Clone, Debug)]
pub struct DeviceInfo {
    /// hidapi path -- passed verbatim to [`Device::open`].
    pub path: String,
    /// USB vendor ID.
    pub vendor_id: u16,
    /// USB product ID.
    pub product_id: u16,
    /// Manufacturer string from the USB descriptor, if any.
    pub manufacturer: Option<String>,
    /// Product string from the USB descriptor, if any.
    pub product: Option<String>,
    /// USB serial number, if any. Authenticators that randomise
    /// their serial per boot will return a fresh value on replug.
    pub serial_number: Option<String>,
}

// ---------- All hidapi use, confined to one thread ----------
//
// `hidapi`'s macOS backend keeps CoreFoundation state -- an
// `IOHIDManager` and its device cache -- behind the C library's globals,
// and CF objects are not safe to touch from more than one thread. Calling
// into it from two threads, even strictly one after the other under a
// mutex, corrupts that state: the process dies inside
// `__CFCheckCFInfoPACSignature` with `EXC_BREAKPOINT`, no panic and no
// message. Locking is not enough because the problem is thread
// *affinity*, not concurrency.
//
// So every hidapi call -- enumeration, open, and each report read and
// write -- is sent to a single worker thread that owns the `HidApi` and
// every open `HidDevice`. Callers hold an opaque [`Handle`] and talk to
// the worker over a channel. Nothing else in this crate touches
// `hidapi`, and nothing hands a `HidDevice` across a thread boundary.
//
// The cost is that concurrent `Device`s serialise. That is what the
// platform requires, and it is honest: previously they did not serialise
// and the process died instead.

/// An open device, as far as callers are concerned. Meaningful only to
/// the worker thread that owns the `HidDevice` behind it.
type Handle = u64;

/// One unit of work for the worker. Each carries the channel its answer
/// goes back on.
enum Job {
    /// Every HID device on the bus, FIDO or not -- for diagnostics.
    ListAll(mpsc::Sender<Result<Vec<RawDeviceInfo>, Error>>),
    /// Just the FIDO ones.
    Enumerate(mpsc::Sender<Result<Vec<DeviceInfo>, Error>>),
    Open {
        path: String,
        reply: mpsc::Sender<Result<Handle, Error>>,
    },
    Write {
        handle: Handle,
        buf: Box<[u8; REPORT_LEN + 1]>,
        reply: mpsc::Sender<Result<usize, Error>>,
    },
    Read {
        handle: Handle,
        timeout_ms: i32,
        reply: mpsc::Sender<Result<(usize, Box<[u8; REPORT_LEN]>), Error>>,
    },
    Close(Handle),
}

/// What `list_all` reports. A plain owned snapshot, because `hidapi`'s
/// own `DeviceInfo` borrows from the context that must not leave the
/// worker thread.
#[derive(Clone, Debug)]
pub struct RawDeviceInfo {
    /// OS-specific device path, as `hidapi` reports it.
    pub path: String,
    /// USB vendor id.
    pub vendor_id: u16,
    /// USB product id.
    pub product_id: u16,
    /// HID usage page. FIDO is 0xF1D0.
    pub usage_page: u16,
    /// HID usage within the page. FIDO is 0x0001.
    pub usage: u16,
    /// Product string from the USB descriptor, if any.
    pub product: Option<String>,
}

static WORKER: OnceLock<mpsc::Sender<Job>> = OnceLock::new();

/// Hand `job` to the worker and wait for the answer.
///
/// The worker is started on first use and lives for the process. It is
/// never joined: there is nothing to flush, and a `HidApi` is documented
/// by the crate as never being deinitialised anyway.
fn submit<T>(build: impl FnOnce(mpsc::Sender<T>) -> Job) -> Result<T, Error> {
    let tx = WORKER.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<Job>();
        std::thread::Builder::new()
            .name("pqf-hidapi".into())
            .spawn(move || run_worker(rx))
            .expect("spawn the hidapi worker thread");
        tx
    });
    let (rtx, rrx) = mpsc::channel::<T>();
    tx.send(build(rtx))
        .map_err(|_| Error::Transport("hidapi worker thread has gone away".into()))?;
    rrx.recv()
        .map_err(|_| Error::Transport("hidapi worker dropped the reply".into()))
}

/// Fire-and-forget, for `Close` on drop: nothing waits for it and a dead
/// worker is not an error the caller can act on.
fn submit_detached(job: Job) {
    if let Some(tx) = WORKER.get() {
        let _ = tx.send(job);
    }
}

/// The only thread that ever calls into `hidapi`.
fn run_worker(rx: mpsc::Receiver<Job>) {
    // Built on first need rather than up front: a process that links
    // this crate but never touches a token should not scan the USB bus.
    let mut api: Option<hidapi::HidApi> = None;
    let mut devices: std::collections::HashMap<Handle, hidapi::HidDevice> =
        std::collections::HashMap::new();
    let mut next_handle: Handle = 1;

    /// Get the context, rescanning if it already exists. The rescan is
    /// what makes hot-plug visible -- a cached list would be a snapshot
    /// of whenever the first call happened.
    fn context<'a>(api: &'a mut Option<hidapi::HidApi>) -> Result<&'a hidapi::HidApi, Error> {
        match api {
            Some(a) => {
                a.refresh_devices()?;
                Ok(a)
            }
            None => {
                *api = Some(hidapi::HidApi::new()?);
                Ok(api.as_ref().expect("just initialised"))
            }
        }
    }

    for job in rx {
        match job {
            Job::ListAll(reply) => {
                let out = context(&mut api).map(|a| {
                    a.device_list()
                        .map(|d| RawDeviceInfo {
                            path: d.path().to_string_lossy().into_owned(),
                            vendor_id: d.vendor_id(),
                            product_id: d.product_id(),
                            usage_page: d.usage_page(),
                            usage: d.usage(),
                            product: d.product_string().map(str::to_string),
                        })
                        .collect()
                });
                let _ = reply.send(out);
            }
            Job::Enumerate(reply) => {
                let out = context(&mut api).and_then(|a| {
                    let mut out = Vec::new();
                    for d in a.device_list() {
                        if d.usage_page() != FIDO_USAGE_PAGE || d.usage() != FIDO_USAGE {
                            continue;
                        }
                        out.push(DeviceInfo {
                            path: d
                                .path()
                                .to_str()
                                .map_err(|_| Error::Transport("hidapi path not utf-8".into()))?
                                .to_string(),
                            vendor_id: d.vendor_id(),
                            product_id: d.product_id(),
                            manufacturer: d.manufacturer_string().map(str::to_string),
                            product: d.product_string().map(str::to_string),
                            serial_number: d.serial_number().map(str::to_string),
                        });
                    }
                    Ok(out)
                });
                let _ = reply.send(out);
            }
            Job::Open { path, reply } => {
                let out = (|| {
                    let cpath = std::ffi::CString::new(path).map_err(|_| {
                        Error::Transport("hidapi path contains an interior NUL".into())
                    })?;
                    let a = context(&mut api)?;
                    let dev = a.open_path(&cpath)?;
                    // Block long enough for the INIT response but not
                    // forever -- bricked devices must surface as Timeout.
                    dev.set_blocking_mode(true)?;
                    let h = next_handle;
                    next_handle += 1;
                    devices.insert(h, dev);
                    Ok(h)
                })();
                let _ = reply.send(out);
            }
            Job::Write { handle, buf, reply } => {
                let out = match devices.get(&handle) {
                    Some(d) => d.write(&buf[..]).map_err(Error::from),
                    None => Err(Error::NoDevice),
                };
                let _ = reply.send(out);
            }
            Job::Read {
                handle,
                timeout_ms,
                reply,
            } => {
                let mut buf = Box::new([0u8; REPORT_LEN]);
                let out = match devices.get(&handle) {
                    Some(d) => d
                        .read_timeout(&mut buf[..], timeout_ms)
                        .map_err(Error::from)
                        .map(|n| (n, buf)),
                    None => Err(Error::NoDevice),
                };
                let _ = reply.send(out);
            }
            Job::Close(handle) => {
                devices.remove(&handle);
            }
        }
    }
}

/// Every HID device on the bus, FIDO or not. Diagnostics only -- the
/// FIDO-filtered list is [`enumerate`].
pub fn list_all() -> Result<Vec<RawDeviceInfo>, Error> {
    submit(Job::ListAll)?
}

/// Walk the OS HID bus and return every device that advertises the
/// FIDO usage page (0xF1D0 / usage 0x0001).
///
/// This is the standard "show the user a list of plugged-in security
/// keys" call. A given physical device may appear more than once if
/// it advertises multiple HID interfaces under the FIDO usage page
/// (some authenticators expose a separate transport or vendor
/// interface alongside FIDO) -- filter by `product` /
/// `serial_number` upstream if you care.
pub fn enumerate() -> Result<Vec<DeviceInfo>, Error> {
    submit(Job::Enumerate)?
}

// ---------- Capabilities ----------

/// CTAPHID INIT capabilities bitmask. Per FIDO U2F HID v1.2 sec. 6.2.4
/// Table 4, plus CTAP 2.1 sec. 11.2.9.1 which adds the CBOR bit.
#[derive(Clone, Copy, Debug)]
pub struct Capabilities(pub u8);

impl Capabilities {
    /// Device implements `CTAPHID_WINK` -- the cosmetic "blink to
    /// identify me" command. Bit 0 (0x01).
    pub fn wink(self) -> bool {
        self.0 & 0x01 != 0
    }
    /// Device implements `CTAPHID_CBOR` (CTAP 2.x). Bit 2 (0x04).
    pub fn cbor(self) -> bool {
        self.0 & 0x04 != 0
    }
    /// Device does **not** implement `CTAPHID_MSG` (U2F / CTAP1).
    /// Bit 3 (0x08). The semantics are flipped from the other
    /// capability bits: NMSG = 1 means "no legacy U2F support".
    pub fn nmsg(self) -> bool {
        self.0 & 0x08 != 0
    }
}

// ---------- Transport counters ----------

/// Transport-level counters accumulated by a [`Device`] since the
/// last [`Device::reset_stats`].
///
/// Exists for callers that need to characterise a transaction, not
/// just perform it -- a benchmark reporting response size and
/// KEEPALIVE count, or a diagnostic confirming the device really is
/// signalling progress during a long ML-DSA sign rather than simply
/// going quiet.
///
/// The counters cover CTAPHID *payload* bytes, not wire bytes: the
/// 7-byte init-frame header, 5-byte continuation headers, and the
/// zero padding on the final frame of a message are excluded, so
/// `rx_bytes` after one CBOR call is exactly the length of the
/// response the authenticator produced.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// `CTAPHID_KEEPALIVE` (0xBB) frames received and discarded.
    /// The authenticator emits one roughly every 100 ms while a
    /// command is still executing, so this doubles as a coarse
    /// measure of how long the device spent working.
    pub keepalives: u32,
    /// Longest silence on the channel while waiting for a response:
    /// the largest interval between two consecutive frames from the
    /// device (KEEPALIVE or data), or between the start of the wait
    /// and the first frame. Where `keepalives` says the device kept
    /// talking, this says how long it ever stopped -- the number a
    /// client-side watchdog would act on.
    pub max_gap: Duration,
    /// Message payload bytes received (KEEPALIVE frames excluded).
    pub rx_bytes: usize,
    /// Message payload bytes sent.
    pub tx_bytes: usize,
}

// ---------- The opened device handle ----------

/// An opened CTAPHID device with an allocated channel ID. Returned
/// by [`Device::open`]. Drop closes the underlying HID handle.
///
/// `Device` is not `Sync` -- concurrent calls would interleave
/// frames on the same channel and the authenticator would respond
/// with `CHANNEL_BUSY`. Wrap in a `Mutex` if you need to share.
pub struct Device {
    /// Opaque to us: the worker thread owns the `HidDevice`.
    handle: Handle,
    cid: u32,
    /// Cached caps from INIT, surfaced via [`Self::capabilities`].
    caps: Capabilities,
    /// Cached protocol version / device version, surfaced via the
    /// matching accessors below.
    proto: u8,
    dev_major: u8,
    dev_minor: u8,
    dev_build: u8,
    /// Transport counters, surfaced via [`Self::stats`]. `Cell`
    /// rather than a `&mut self` on every send/recv: the counters
    /// are incidental bookkeeping and forcing every caller to hold
    /// a mutable borrow of the device just to read a response would
    /// be a poor trade. `Device` is already documented as not
    /// `Sync`, so interior mutability costs nothing here.
    stats: Cell<Stats>,
}

impl Device {
    /// Open a FIDO HID device by the path returned in [`DeviceInfo`].
    /// Performs the CTAPHID INIT handshake before returning -- on
    /// success the [`Device`] has an allocated CID and can speak
    /// CTAP 2.x commands.
    pub fn open(info: &DeviceInfo) -> Result<Self, Error> {
        let path = info.path.clone();
        let handle = submit(|reply| Job::Open { path, reply })??;
        match Self::with_handle(handle) {
            Ok(d) => Ok(d),
            Err(e) => {
                // INIT failed: the worker is still holding an open
                // device that no `Device` will ever drop.
                submit_detached(Job::Close(handle));
                Err(e)
            }
        }
    }

    /// Run CTAPHID INIT against an already-open worker handle.
    fn with_handle(handle: Handle) -> Result<Self, Error> {
        // CTAPHID INIT -- payload is 8 random bytes used as a nonce
        // that the device echoes back so we can confirm the
        // response wasn't from someone else's conversation on the
        // broadcast channel (FIDO U2F HID v1.2 sec. 6.7). The spec calls
        // for 8 unpredictable bytes; fill them from the OS CSPRNG so
        // the nonce can't be guessed or reconstructed from observable
        // state (PID, startup counter, elapsed time).
        let mut nonce = [0u8; 8];
        rand::Rng::fill(&mut OsRng, &mut nonce[..]);

        // Send INIT on the broadcast channel.
        send_message(handle, BROADCAST_CID, Cmd::Init.as_byte(), &nonce)?;
        // INIT is answered immediately, so the keepalive count here
        // is expected to be zero; it is discarded either way because
        // the handshake predates the `Device` the counters live on.
        let mut init_keepalives = 0u32;
        let mut init_gap = Duration::ZERO;
        let (resp_cid, resp_cmd, resp_data) =
            recv_message(handle, BROADCAST_CID, &mut init_keepalives, &mut init_gap)?;
        if resp_cmd != Cmd::Init.as_byte() {
            return Err(Error::Transport(format!(
                "INIT response had unexpected cmd 0x{resp_cmd:02x}"
            )));
        }
        if resp_data.len() < 17 {
            return Err(Error::Transport(format!(
                "INIT response too short: {} bytes",
                resp_data.len()
            )));
        }
        if resp_data[0..8] != nonce {
            return Err(Error::NonceMismatch);
        }
        let cid = u32::from_be_bytes([resp_data[8], resp_data[9], resp_data[10], resp_data[11]]);
        let proto = resp_data[12];
        let dev_major = resp_data[13];
        let dev_minor = resp_data[14];
        let dev_build = resp_data[15];
        let caps = Capabilities(resp_data[16]);

        // `resp_cid` from the device should be the broadcast CID
        // since we asked on broadcast; some authenticators (notably
        // older U2F devices) reply on the newly-allocated CID instead.
        // Accept either -- `cid` is the source of truth.
        let _ = resp_cid;

        Ok(Self {
            handle,
            cid,
            caps,
            proto,
            dev_major,
            dev_minor,
            dev_build,
            stats: Cell::new(Stats::default()),
        })
    }

    /// Channel ID this host was allocated by the device's INIT
    /// response.
    pub fn cid(&self) -> u32 {
        self.cid
    }

    /// Capabilities byte from the INIT response.
    pub fn capabilities(&self) -> Capabilities {
        self.caps
    }

    /// CTAPHID protocol version (currently always 2 -- FIDO U2F HID
    /// v1.2 sec. 6.2.4 Table 4).
    pub fn ctaphid_version(&self) -> u8 {
        self.proto
    }

    /// Device firmware version, as the device chose to advertise it
    /// in its INIT response. Three bytes: major / minor / build.
    pub fn firmware_version(&self) -> (u8, u8, u8) {
        (self.dev_major, self.dev_minor, self.dev_build)
    }

    /// Send a complete CTAPHID message on this device's channel.
    /// `payload.len()` must be <= [`MAX_MSG_LEN`] (~ 7.6 KiB);
    /// larger requests aren't representable in CTAPHID framing.
    pub fn send_msg(&self, cmd: Cmd, payload: &[u8]) -> Result<(), Error> {
        self.send_raw(cmd.as_byte(), payload)
    }

    /// [`Self::send_msg`] by on-wire command byte (init bit set): the
    /// path shared with [`Self::vendor`], whose commands have no
    /// [`Cmd`] variant.
    fn send_raw(&self, cmd: u8, payload: &[u8]) -> Result<(), Error> {
        send_message(self.handle, self.cid, cmd, payload)?;
        let mut s = self.stats.get();
        s.tx_bytes += payload.len();
        self.stats.set(s);
        Ok(())
    }

    /// Snapshot of this device's [`Stats`] since the last
    /// [`Self::reset_stats`] (or since [`Self::open`]).
    pub fn stats(&self) -> Stats {
        self.stats.get()
    }

    /// Zero the transport counters. Call immediately before the
    /// transaction you want to measure so the returned [`Stats`]
    /// describe that transaction alone.
    pub fn reset_stats(&self) {
        self.stats.set(Stats::default());
    }

    /// Receive a complete CTAPHID message on this device's channel.
    /// Filters out `CTAPHID_KEEPALIVE` (0xBB) frames transparently --
    /// the caller sees only the eventual real response. The
    /// discarded frames are still counted, into
    /// [`Stats::keepalives`].
    ///
    /// Returns the command byte alongside the payload so callers
    /// that send `CTAPHID_PING` and want to verify the echo can
    /// pattern-match on it. CTAP 2.x callers will essentially
    /// always see `Cmd::Cbor` (in response to their CBOR sends) or
    /// `Cmd::Error` (on a transport-level failure).
    pub fn recv_msg(&self, expected_cmd: Cmd) -> Result<Vec<u8>, Error> {
        let (cmd, data) = self.recv_raw()?;
        if cmd != expected_cmd.as_byte() {
            return Err(Error::Transport(format!(
                "expected cmd 0x{:02x}, got 0x{cmd:02x}",
                expected_cmd.as_byte()
            )));
        }
        Ok(data)
    }

    /// The receive path under [`Self::recv_msg`] and [`Self::vendor`]:
    /// one message on this channel, KEEPALIVE frames filtered and
    /// counted, `CTAPHID_ERROR` surfaced as [`Error::HidError`].
    /// Returns the on-wire command byte with the payload; the caller
    /// checks it against the command it sent.
    fn recv_raw(&self) -> Result<(u8, Vec<u8>), Error> {
        let mut keepalives = 0u32;
        let mut max_gap = Duration::ZERO;
        let recvd = recv_message(self.handle, self.cid, &mut keepalives, &mut max_gap);
        // Account for the keepalives even when the read ultimately
        // failed -- a timeout preceded by 40 keepalives is a very
        // different diagnosis from one preceded by none.
        let mut s = self.stats.get();
        s.keepalives += keepalives;
        s.max_gap = s.max_gap.max(max_gap);
        if let Ok((_, _, ref data)) = recvd {
            s.rx_bytes += data.len();
        }
        self.stats.set(s);
        let (cid, cmd, data) = recvd?;
        if cid != self.cid {
            return Err(Error::Transport(format!(
                "frame for wrong cid 0x{cid:08x} (expected 0x{:08x})",
                self.cid
            )));
        }
        if cmd == Cmd::Error.as_byte() {
            // Spec mandates exactly one byte of payload -- the error
            // code. Some buggy devices send more; we use the first.
            let code = data.first().copied().unwrap_or(hid_err::OTHER);
            return Err(Error::HidError(code));
        }
        Ok((cmd, data))
    }

    /// Send a CTAPHID PING (CMD 0x81) with the given payload and
    /// wait for the echo. Returns the echoed bytes. Verifies that
    /// the device sent back exactly what we sent.
    pub fn ping(&self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        self.send_msg(Cmd::Ping, payload)?;
        let echoed = self.recv_msg(Cmd::Ping)?;
        if echoed != payload {
            return Err(Error::Transport(
                "PING echo did not match the bytes we sent".into(),
            ));
        }
        Ok(echoed)
    }

    /// Send a CTAPHID WINK (CMD 0x88). Empty request, empty
    /// response. Most devices flash an LED; some ignore the
    /// command entirely.
    pub fn wink(&self) -> Result<(), Error> {
        self.send_msg(Cmd::Wink, &[])?;
        let _ = self.recv_msg(Cmd::Wink)?;
        Ok(())
    }

    /// Send a CTAPHID CANCEL (CMD 0x91). Tells the device to abort
    /// the currently-pending command on this channel. CTAP 2.1 sec. 11.2.9.2 --
    /// no response is generated by the device for CANCEL itself, but
    /// the in-flight command's response arrives carrying the CTAP2
    /// error code `0x2D` (`ERR_KEEPALIVE_CANCEL`).
    ///
    /// # Caller obligation: drain the cancelled response
    ///
    /// `cancel` only writes the CANCEL frame; it does **not** read.
    /// Because the authenticator still emits the aborted command's
    /// response frame (CBOR status `0x2D`), the caller MUST follow a
    /// `cancel()` with a [`recv_msg`](Self::recv_msg) to drain that
    /// response off the channel before issuing the next command.
    /// Skipping the drain leaves the `0x2D` reply queued, so the
    /// following command's [`recv_msg`](Self::recv_msg) returns the
    /// stale cancellation instead of its own answer. (A full
    /// implementation would also re-INIT or otherwise reset channel
    /// state if the drain times out; that broader recovery is not
    /// handled here.)
    pub fn cancel(&self) -> Result<(), Error> {
        self.send_msg(Cmd::Cancel, &[])
    }

    /// Fill `out` with raw TRNG bytes from the device via the vendor
    /// command `CTAPHID_CMD_RNG` ([`Cmd::Rng`]).
    ///
    /// Each transaction requests up to [`RNG_MAX_XACT`] bytes (the
    /// firmware's per-request ceiling); larger buffers are filled over
    /// several round trips. The request payload is the chunk size as a
    /// 2-byte big-endian count and the device answers with exactly that
    /// many bytes. Mirrors the C client's `pqhid_rng()`.
    ///
    /// No authentication and no user-presence gesture is involved -- the
    /// entropy is not a secret; consumers (the PKCS#11 module, OpenSSL's
    /// pkcs11 provider) mix it into their own pool. A device whose
    /// firmware predates the vendor command answers `CTAPHID_ERROR`
    /// (`ERR_INVALID_CMD`), surfaced here as [`Error::HidError`].
    pub fn rng(&self, out: &mut [u8]) -> Result<(), Error> {
        let mut done = 0;
        while done < out.len() {
            let want = core::cmp::min(out.len() - done, RNG_MAX_XACT);
            let req = (want as u16).to_be_bytes();
            self.send_msg(Cmd::Rng, &req)?;
            let resp = self.recv_msg(Cmd::Rng)?;
            if resp.len() != want {
                return Err(Error::Transport(format!(
                    "CMD_RNG returned {} bytes, asked for {want}",
                    resp.len()
                )));
            }
            out[done..done + want].copy_from_slice(&resp);
            done += want;
        }
        Ok(())
    }

    /// Ask the device to reboot via the vendor command
    /// `CTAPHID_CMD_REBOOT` ([`Cmd::Reboot`]).
    ///
    /// [`RebootMode::Bootsel`] drops it into the RP2350 USB bootloader
    /// (mass storage / DFU) for reflashing; [`RebootMode::Warm`]
    /// restarts the firmware. BOTH modes are gated behind a test of
    /// user presence on the device: on a board with a user button the
    /// firmware blocks until the user touches the key (shipping
    /// `KEEPALIVE`-`UPNEEDED` meanwhile) before it reboots; on a
    /// buttonless build it reboots immediately.
    ///
    /// This is fire-and-forget: the device disconnects from the bus on
    /// success, so no response frame is awaited -- it sends the one-byte
    /// request and returns once that is on the wire. Callers should
    /// then poll for the device to re-appear (as a BOOTSEL mass-storage
    /// device, or as the FIDO device again after a warm reboot). A
    /// device whose firmware predates the command answers
    /// `CTAPHID_ERROR` (`ERR_INVALID_CMD`); since we do not read a
    /// reply, detect that by observing that the device never rebooted.
    /// Mirrors the C client's `pqhid_reboot()`.
    pub fn reboot(&self, mode: RebootMode) -> Result<(), Error> {
        self.send_msg(Cmd::Reboot, &[mode as u8])
    }

    /// Send an arbitrary vendor CTAPHID command and read its one reply.
    ///
    /// `cmd` is the command number -- CTAP 2.1 sec. 11.2.9.2 reserves
    /// 0x40..=0x7f for vendors -- and the init bit is set here, so
    /// `0x42` and `0xc2` name the same command. The device answers on
    /// that same command byte and the reply's payload is returned.
    /// Anything else is an error: `CTAPHID_ERROR` (`ERR_INVALID_CMD`
    /// from a build that lacks the command) as [`Error::HidError`], a
    /// reply on some other command byte as [`Error::Transport`].
    ///
    /// The untyped counterpart of [`Self::rng`] and [`Self::reboot`],
    /// for the dev-only commands a test image exposes (presence
    /// injection, register probes, last-CBOR echo) that have no [`Cmd`]
    /// variant of their own. Nothing is gated on the host side; whatever
    /// gating there is belongs to the firmware.
    pub fn vendor(&self, cmd: u8, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let wire = cmd | 0x80;
        self.send_raw(wire, payload)?;
        let (got, data) = self.recv_raw()?;
        if got != wire {
            return Err(Error::Transport(format!(
                "vendor cmd 0x{wire:02x} was answered on cmd 0x{got:02x}"
            )));
        }
        Ok(data)
    }

    /// Release the worker's `HidDevice` when the last handle goes.
    ///
    /// Without this the worker accumulates open devices for the life of
    /// the process, and on macOS a still-open exclusive handle stops the
    /// next `open_path` on the same token.
    fn close(&self) {
        submit_detached(Job::Close(self.handle));
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        self.close();
    }
}

// ---------- Framing internals ----------
//
// These are free fns rather than methods on `Device` so the INIT
// handshake (which doesn't have a `Device` yet) can share the
// same code path.

/// Split `payload` into init + continuation frames and write each
/// 64-byte report to the HID endpoint. `cmd` is the on-wire command
/// byte, init bit included: a [`Cmd::as_byte`], or a vendor command
/// number the [`Cmd`] enum has no variant for.
fn send_message(handle: Handle, cid: u32, cmd: u8, payload: &[u8]) -> Result<(), Error> {
    if payload.len() > MAX_MSG_LEN {
        return Err(Error::OversizedMessage {
            announced: payload.len(),
            max: MAX_MSG_LEN,
        });
    }

    // First frame -- init. `frame::build_init_frame` names the command
    // as a `Cmd`, which cannot spell a vendor command, so it lays the
    // frame out under a placeholder and the CMD byte (offset 4 -- see
    // `frame`) is written over it here.
    let (mut init_frame, init_taken) = frame::build_init_frame(cid, Cmd::Ping, payload);
    init_frame[4] = cmd;
    write_report(handle, &init_frame)?;
    let mut sent = init_taken;
    // Continuation frames.
    let mut seq: u8 = 0;
    while sent < payload.len() {
        let (cont_frame, cont_taken) = frame::build_cont_frame(cid, seq, &payload[sent..]);
        write_report(handle, &cont_frame)?;
        sent += cont_taken;
        seq = seq.wrapping_add(1);
    }
    Ok(())
}

/// Read frames until a complete message arrives on the expected CID,
/// discarding KEEPALIVE frames and frames for other channels.
/// Returns `(cid, cmd, payload)` once the message is fully
/// reassembled, where `cmd` is the on-wire command byte as the device
/// sent it: `frame::parse_frame` folds bytes it has no [`Cmd`] for
/// into `Cmd::Error`, and a vendor reply is matched on the byte.
///
/// `keepalives` is incremented once per discarded KEEPALIVE frame on
/// our own channel, including on the error paths, so a caller can
/// report how hard the device was working even when the transaction
/// ultimately timed out. `max_gap` is raised to the longest interval
/// seen between consecutive frames on our channel (see
/// [`Stats::max_gap`]); frames for other channels do not count as
/// the device talking to us.
fn recv_message(
    handle: Handle,
    expected_cid: u32,
    keepalives: &mut u32,
    max_gap: &mut Duration,
) -> Result<(u32, u8, Vec<u8>), Error> {
    // Total wall-clock budget so a misbehaving device can't strand
    // us forever. CTAPHID_KEEPALIVE resets the budget -- the device
    // is signalling progress every <=100 ms, so we only get here
    // when it actually goes silent.
    let total_budget = Duration::from_millis((READ_TIMEOUT_MS as u64).saturating_mul(20));
    let start = Instant::now();
    let mut last_frame = start;
    let seen = |last: &mut Instant, max_gap: &mut Duration| {
        let now = Instant::now();
        *max_gap = (*max_gap).max(now - *last);
        *last = now;
    };

    'outer: loop {
        if start.elapsed() > total_budget {
            return Err(Error::Timeout);
        }
        let report = read_report(handle)?;
        match frame::parse_frame(&report) {
            Some(frame::Parsed::Init(p)) => {
                // Frame for someone else's conversation -- silently
                // ignore. The OS HID stack already filters by usage
                // page, so this is rare in practice but possible
                // when multiple processes hold the same device.
                if expected_cid != BROADCAST_CID && p.cid != expected_cid {
                    continue;
                }
                seen(&mut last_frame, max_gap);
                if p.cmd == Cmd::Keepalive {
                    // CTAP 2.1 sec. 11.2.9.1.7 -- single status byte,
                    // ignore the content. Reset the watchdog by
                    // letting the outer loop tick.
                    *keepalives += 1;
                    continue;
                }
                let raw_cmd = report[4];
                let total = p.bcnt as usize;
                if total > MAX_MSG_LEN {
                    return Err(Error::OversizedMessage {
                        announced: total,
                        max: MAX_MSG_LEN,
                    });
                }
                let mut buf = Vec::with_capacity(total);
                let take = core::cmp::min(total, p.payload.len());
                buf.extend_from_slice(&p.payload[..take]);
                if buf.len() == total {
                    return Ok((p.cid, raw_cmd, buf));
                }
                // Need more frames.
                let mut next_seq: u8 = 0;
                while buf.len() < total {
                    if start.elapsed() > total_budget {
                        return Err(Error::Timeout);
                    }
                    let report = read_report(handle)?;
                    let cont = match frame::parse_frame(&report) {
                        Some(frame::Parsed::Cont(c)) => c,
                        Some(frame::Parsed::Init(ip)) => {
                            // An init-shaped frame arrived in the
                            // middle of reassembly. Two benign cases
                            // must NOT discard the partial `buf`:
                            //
                            //   * a CTAPHID_KEEPALIVE on our own
                            //     channel -- CTAP 2.1 sec. 11.2.9.1.7, the
                            //     device signalling progress; skip it
                            //     and keep collecting;
                            //   * any frame for a foreign channel --
                            //     another process's conversation
                            //     bleeding in; not ours to act on.
                            //
                            // Only a genuine (non-keepalive) init on
                            // our own channel means the device tore
                            // down this transaction and started a new
                            // message, so restart reassembly from the
                            // top for that case alone.
                            let foreign = expected_cid != BROADCAST_CID && ip.cid != expected_cid;
                            if !foreign {
                                seen(&mut last_frame, max_gap);
                            }
                            if ip.cmd == Cmd::Keepalive || foreign {
                                if ip.cmd == Cmd::Keepalive && !foreign {
                                    *keepalives += 1;
                                }
                                continue;
                            }
                            continue 'outer;
                        }
                        None => return Err(Error::ShortRead(report.len())),
                    };
                    if cont.cid != p.cid {
                        // Foreign continuation -- another channel's
                        // frame bled in. Skip it without disturbing
                        // the reassembly already in progress.
                        continue;
                    }
                    seen(&mut last_frame, max_gap);
                    if cont.seq != next_seq {
                        return Err(Error::SequenceMismatch {
                            expected: next_seq,
                            got: cont.seq,
                        });
                    }
                    let remaining = total - buf.len();
                    let take = core::cmp::min(remaining, cont.payload.len());
                    buf.extend_from_slice(&cont.payload[..take]);
                    next_seq = next_seq.wrapping_add(1) & 0x7f;
                }
                return Ok((p.cid, raw_cmd, buf));
            }
            Some(frame::Parsed::Cont(_)) => {
                // Cont frame with no preceding init -- stray packet.
                // Discard and try again.
                continue;
            }
            None => return Err(Error::ShortRead(report.len())),
        }
    }
}

/// One 64-byte write to the HID interrupt-out endpoint. hidapi
/// expects a report-ID-prefixed buffer; on FIDO HID the report ID
/// is always 0 (no report IDs in the descriptor) so we prepend a
/// 0x00 byte before the 64-byte payload.
fn write_report(handle: Handle, report: &[u8; REPORT_LEN]) -> Result<(), Error> {
    let mut buf = Box::new([0u8; REPORT_LEN + 1]);
    // buf[0] = 0x00 (report ID 0 -- already zero from initialiser).
    buf[1..].copy_from_slice(report);
    let len = buf.len();
    let written = submit(|reply| Job::Write { handle, buf, reply })??;
    if written < len {
        return Err(Error::Transport(format!(
            "short HID write: {written} of {len} bytes"
        )));
    }
    Ok(())
}

/// One 64-byte read from the HID interrupt-in endpoint. hidapi
/// returns the report without the leading report ID byte (since
/// the descriptor has no report IDs), so the buffer is already
/// exactly 64 bytes long.
fn read_report(handle: Handle) -> Result<[u8; REPORT_LEN], Error> {
    let (n, buf) = submit(|reply| Job::Read {
        handle,
        timeout_ms: READ_TIMEOUT_MS,
        reply,
    })??;
    if n == 0 {
        return Err(Error::Timeout);
    }
    if n != REPORT_LEN {
        return Err(Error::ShortRead(n));
    }
    Ok(*buf)
}
