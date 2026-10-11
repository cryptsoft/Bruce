# Hardware

The supported target boards and how the firmware drives their on-board
peripherals: pinouts, the user-presence buttons, the USB descriptor,
the entropy sources, the memory map, and how to add a board. It is
for anyone wiring, choosing or porting to a board, and assumes nothing
beyond the board itself. The from-scratch path is
[GETTING-STARTED.md](GETTING-STARTED.md); build options are in
[BUILD.md](BUILD.md), the per-board BOOTSEL and flashing recipes in
[FLASHING.md](FLASHING.md), and what the LEDs mean day to day in
[USAGE.md](USAGE.md).

Contents:

- [User-presence buttons](#user-presence-buttons)
- [Adding a new board](#adding-a-new-board)
- [Board: Pimoroni Tiny 2350](#board-pimoroni-tiny-2350)
- [Board: Seeed Studio XIAO RP2350](#board-seeed-studio-xiao-rp2350)
- [GPIO assignments](#gpio-assignments) (all six boards)
- [LED state machine](#led-state-machine)
- [BOOT button (QSPI_SS)](#boot-button-qspi_ss)
- [USB descriptor](#usb-descriptor)
- [TRNG](#trng-cratesfirmwaresrctrngrs)
- [QRNG over I2C (optional)](#qrng-over-i2c-optional)
- [Memory map](#memory-map)
- [Picotool metadata](#picotool-metadata)
- [Why no boot stage 2?](#why-no-boot-stage-2)
- [Power and current](#power-and-current)
- [Hardware in summary](#hardware-in-summary)

Six boards are supported out of the box, selected at compile time via mutually-exclusive cargo features (the C firmware takes the same six as `-DPQF_BOARD=`, see below):

  - **`board_tiny2350`** (default) -- Pimoroni Tiny 2350. Three-channel RGB LED on discrete pins. **Real user presence** via the on-board BOOT button, sampled at runtime through the QSPI chip-select line exactly as on the Feitian, or an external touch button / momentary switch on GP0 (see "User-presence buttons" below).
  - **`board_xiao_rp2350`** -- Seeed Studio XIAO RP2350. Single dual-colour user LED on GP25; NeoPixel power on GP23 must be driven LOW (the firmware does this -- see "GP23 quirk" below).
  - **`board_feitian_rp2350`** -- Feitian RP2350, a faithful Raspberry Pi Pico 2 reference-design build (schematic `PICO2_G9_QE09_V1.0`). Single green user LED on GP25, **active-high** (opposite polarity to the XIAO's GP25 -- they cannot share a profile). **Real user presence** via the BOOTSEL button, sampled at runtime through the QSPI chip-select line (see "User-presence buttons" below).
  - **`board_waveshare_rp2350_lcd_1_47`** -- Waveshare RP2350-LCD-1.47 in its -A, -B and -B-M variants (Pico 2 footprint + 1.47" 172x320 ST7789V2 LCD + micro-SD + WS2812 RGB chain on GP23; the variants share one GPIO map and differ only in USB connector and headers). The firmware drives the **LCD as a live device-stats panel**; SD untouched; WS2812 held in reset (lamps dark) until a PIO driver lands.
  - **`board_spotpear_rp2350_lcd_1_28`** -- Spotpear RP2350-LCD-1.28 (round 1.28" 240x240 GC9A01 IPS LCD + QMI8658 IMU + battery connector). The firmware drives the **round LCD as a centred stats panel**; the IMU and battery ADC are untouched.
  - **`board_feitian_rp2350_usbc`** -- Feitian RP2350 USB-C token: the Feitian RP2350's hardware profile in a **sealed USB-C case** with a **capacitive touch pad** instead of the button, no display, and **no working power-on BOOTSEL**. **Real user presence** via the pad, read by the same QSPI chip-select sampler (validated on one production token on 2026-10-02). Experimental: one token so far. Because nothing but the firmware can put it back into the bootloader, its `CTAPHID_CMD_REBOOT` never waits for a touch -- see [its section below](#feitian-rp2350-usb-c-token-board_feitian_rp2350_usbc) and [the USB-C token section of FLASHING.md](FLASHING.md#the-feitian-usb-c-token), which is the only procedure for flashing one.

All six boards use the same RP2350A SoC, USB peripheral, TRNG, and `IMAGE_DEF` ARM-Secure image attestation. They differ in flash size (4 MiB on the Tiny / XIAO / Spotpear; 2 MiB measured on the Feitian RP2350 samples and assumed for the USB-C token; 16 MiB on the Waveshare) and in status-surface + button pinout. The CTAP protocol behaviour is identical across all six, except that the three boards with a presence input (Tiny 2350, Feitian RP2350, the USB-C token) enforce a real user-presence gesture where the others auto-confirm, and that `CTAPHID_CMD_REBOOT` waits for a press only on the two that also have a power-on BOOTSEL (Tiny 2350, Feitian RP2350; see [REBOOT.md](REBOOT.md#user-presence)).

> **C port.** The C firmware (`c/firmware/`) supports the same six
> boards via CMake `-DPQF_BOARD=<name>`; its per-board pin profiles
> live in `c/firmware/src/board.c` and copy the pin numbers from the
> Rust profiles documented here. The C port does not drive the LCD
> panels (LED-or-nothing status surface). Its Tiny 2350, Feitian RP2350
> and USB-C token profiles have the same QSPI_SS user-presence gate
> (`c/firmware/src/bootsel.c`), and `src/board.h` derives the same
> reboot policy from `PQF_BOARD_HAS_USER_BUTTON` and
> `PQF_BOARD_HAS_POWER_ON_BOOTSEL`.

## User-presence buttons

CTAP requires a "test of user presence" before MakeCredential and
GetAssertion. Boards that export `HAS_USER_BUTTON = true` enforce it
with a real gesture -- a fresh release->press held >= 20 ms, within a
10 s window, while the LED blinks and `KEEPALIVE(UPNEEDED)` frames
tell the browser to show "touch your key"; timing out returns
`CTAP2_ERR_OPERATION_DENIED` (0x27; both ports use that name and
number). Boards without a readable
button auto-confirm after the same LED/keepalive machinery.

  - **Tiny 2350 -- BOOT button, plus an optional GP0 touch input.** The
    on-board BOOT button is on QSPI_SS and is read at runtime with the
    same chip-select sampler as the Feitian below (both ports; one
    sample per 2 ms, cached in between). No extra part is needed. An
    external TTP223-style capacitive touch module or plain momentary
    switch wired to GP0 is read as well (Rust port). Its polarity is
    auto-detected at boot -- the
    firmware samples GP0 under a pull-down then a pull-up; agreement
    means a driven (push-pull) module and learns its idle level,
    disagreement means a floating pin and assumes switch-to-GND. The
    verdict is flashed on the LED at boot (green = driven module
    found, red = floating/assumed-switch). Don't touch the pad while
    plugging in -- the probe learns the untouched level then.
  - **Feitian RP2350 -- BOOTSEL as the user button.** The board's only
    button shorts the flash chip-select (QSPI_SS) to ground -- not a
    GPIO, unreadable by ordinary pin reads. The firmware samples it at
    runtime by briefly floating the chip-select pad and reading the
    line through SIO's HI GPIO bank (a few microseconds of flash
    blackout per sample, rate-limited to one sample per 2 ms; the
    routine runs from RAM with interrupts masked). Held at power-on
    the button still enters BOOTSEL mode for flashing; tapped at
    runtime it's just a button. Derived from Raspberry Pi
    pico-examples (BSD-3-Clause) -- see `crates/firmware/src/board/bootsel.rs`,
    `c/firmware/src/bootsel.c`, and THIRD_PARTY.md.
  - **Feitian RP2350 USB-C token -- the touch pad.** The token has no
    button; its capacitive pad is the presence input. The profile reads
    it with the same QSPI_SS sampler as the Feitian RP2350's button.
    That began as a working assumption from the one USB-C sample seen
    (its pad registered as a press at runtime through that sampler,
    while holding it at power-on did not enter BOOTSEL) and was
    **confirmed on the first production token on 2026-10-02**: register
    and login through the pad at the first attempt
    ([TESTING.md](TESTING.md#the-first-production-usb-c-token-2026-10-02)).
    If a later batch wires the pad differently, FIDO presence times out
    (`CTAP2_ERR_OPERATION_DENIED`) but the token stays reflashable,
    because its `CTAPHID_CMD_REBOOT` does not depend on the pad.

## Adding a new board

Board-specific configuration lives in a dedicated directory -- one file per supported board:

```
crates/firmware/src/board/
|-- mod.rs                          # cfg dispatch + compile_error guards + interface contract
|-- bootsel.rs                      # the QSPI chip-select sampler (Tiny 2350 and Feitian BOOT button, USB-C token pad)
|-- tiny2350.rs                     # Pimoroni Tiny 2350
|-- xiao_rp2350.rs                  # Seeed Studio XIAO RP2350
|-- feitian_rp2350.rs               # Feitian RP2350 (Pico 2 reference design)
|-- feitian_rp2350_usbc.rs          # Feitian RP2350 USB-C token (re-exports feitian_rp2350's Board)
|-- waveshare_rp2350_lcd_1_47/      # Waveshare 1.47" (mod.rs + lcd.rs ST7789V2 stats panel)
+-- spotpear_rp2350_lcd_1_28/       # Spotpear round 1.28" (mod.rs + lcd.rs GC9A01 stats panel)
```

`main.rs` only ever references `crate::board::Board` (the cfg-aliased active board) -- it never branches on board features directly. Adding support for a new RP2350-based dev board is four local edits, no changes to `main.rs`:

1. Add a `board_<name> = []` feature line in `Cargo.toml` under `[features]`.
2. Drop a new `crates/firmware/src/board/<name>.rs` into the directory. Use `crates/firmware/src/board/tiny2350.rs` (simple RGB) or `crates/firmware/src/board/xiao_rp2350.rs` (single LED with OR-merge + power-gate quirk) as a template; a board that differs from an existing one only in its case or identity re-exports that profile's `Board`, as `feitian_rp2350_usbc.rs` does. The interface contract -- `Board::setup(pins)`, `r_on/r_off/g_on/g_off/b_on/b_off`, `user_present()`, and the consts `NAME`, `USB_PRODUCT`, `HAS_USER_BUTTON`, `HAS_POWER_ON_BOOTSEL`, `BI_BOARD`, `BI_DESCRIPTION` -- is documented at the top of `crates/firmware/src/board/mod.rs`. Set **`HAS_POWER_ON_BOOTSEL`** from what the hardware has been seen to do, not from the schematic: `true` only if holding a button while plugging in has been observed to bring up the ROM bootloader, `false` if in doubt. With `HAS_USER_BUTTON` it decides whether `CTAPHID_CMD_REBOOT` waits for a touch ([REBOOT.md](REBOOT.md#user-presence)); a wrong `true` on a board with a presence input gates the only way back into the bootloader on a touch that might never register.
3. Add the cfg arm to `crates/firmware/src/board/mod.rs`:
   ```rust
   #[cfg(feature = "board_<name>")]
   mod <name>;
   #[cfg(feature = "board_<name>")]
   pub use <name>::*;
   ```
   Also update the `compile_error!` guards and their messages to mention the new feature.
4. Add the board to the reboot-policy host test, `crates/firmware-hosttest/tests/reboot_policy.rs`, and its name to the `build.sh` board list.

The C port's equivalent is a `PQF_BOARD` branch in `c/firmware/CMakeLists.txt`, a profile in `src/board.c`, and the two capability macros `PQF_BOARD_HAS_USER_BUTTON` / `PQF_BOARD_HAS_POWER_ON_BOOTSEL` in `src/board.h`.

`main.rs` picks up the new board via `pub use <name>::*;` re-export -- no changes there. Build with `cargo build --release --no-default-features --features mldsa65,board_<name>` and you're done. Document any board quirks (power-gate pins, weirdly-wired BOOT buttons, alternative LED arrangements) in the submodule's top doc-comment for the next person who debugs it.

## Board: Pimoroni Tiny 2350

[Pimoroni Tiny 2350 product page](https://shop.pimoroni.com/products/tiny-2350) -- a 22.9 x 18.2 mm RP2350-based dev board. The firmware doesn't use anything board-specific other than the on-board RGB LED and the BOOT button -- it should also run on the Raspberry Pi Pico 2 or any other RP2350A breakout with minor GPIO adjustments.

| Item                          | Value                                                                |
| ---                           | ---                                                                  |
| **SoC**                       | RP2350A (dual Arm Cortex-M33, ARMv8-M with FPU + DSP + TrustZone)    |
| **CPU clock**                 | 125 MHz (PLL_SYS, both cores)                                        |
| **SRAM**                      | 520 KiB, striped across 8 banks                                      |
| **Flash**                     | 4 MiB QSPI, XIP at `0x10000000`                                      |
| **USB**                       | USB 1.1 full-speed device peripheral with internal PHY                |
| **TRNG**                      | Ring-oscillator true RNG, 192 bits / collection cycle                 |
| **Boot ROM features used**    | `connect_internal_flash` + `flash_exit_xip` + `flash_range_erase` + `flash_range_program` + `flash_flush_cache` + `flash_enter_cmd_xip` for credential-store persistence; `IMAGE_DEF` + `binary_info` for `picotool info` |
| **Image attestation**         | ARM-Secure (no signature -- `hal::block::ImageDef::secure_exe()`)      |

The firmware boots in the **secure** ARMv8-M security state (the boot ROM hands control to `cortex-m-rt`'s reset vector in that state by default). TrustZone partitioning isn't used -- everything runs secure.

## Board: Seeed Studio XIAO RP2350

[Seeed Studio XIAO RP2350 product page](https://www.seeedstudio.com/Seeed-XIAO-RP2350-p-5944.html) -- a 21 x 17.5 mm RP2350-based dev board in the XIAO form factor. Differs from the Tiny 2350 in three ways relevant to this firmware: (1) the user LED is a single dual-colour red/yellow LED on GP25, not a three-channel RGB; (2) GP23 is the WS2812 NeoPixel power-enable; (3) GP22 is the WS2812 NeoPixel data line. Everything else (SoC, USB, flash, TRNG) is the same as the Tiny 2350.

| Item                                         | Value                                                                                                                  |
| ---                                          | ---                                                                                                                    |
| **User LED**                                 | GP25, dual-colour red/yellow through 1 kohm resistors to +3V3 (active-low: drive low to light)                          |
| **WS2812 NeoPixel data**                     | GP22 (firmware never drives this -- left floating, NeoPixel stays dark because its power is off)                        |
| **WS2812 NeoPixel power enable**             | GP23 -- drives the EN pin of U7 (SX1801CCR load switch). **HIGH = NeoPixel 5V on; LOW = off.** Firmware drives LOW.    |
| **BOOT button (B)**                          | On QSPI_SS, only readable by the bootrom -- firmware can't poll it                                                     |
| **RESET button (R)**                         | Pulses the chip RUN pin -- for entering BOOTSEL (hold B + tap R + release B) or kicking the firmware                  |
| **Schematic reference**                      | [Seeed XIAO RP2350 v1.0 schematic PDF](https://files.seeedstudio.com/wiki/XIAO-RP2350/res/Seeed-Studio-XIAO-RP2350-v1.0.pdf) |

### The GP23 quirk

The very first port to the XIAO had USB enumeration failing intermittently: Chrome would sometimes detect the device, sometimes not; `picotool` would sometimes find the device in BOOTSEL, sometimes not. Diagnosing took a debug pass through the Seeed schematic.

GP23 on the XIAO RP2350 is the EN pin of an SX1801CCR load switch (U7) that gates 5V (from VBUS) to the WS2812 NeoPixel. Active-high: drive GP23 HIGH and the NeoPixel power rail comes up.

The firmware originally claimed GP23 as a pull-up input -- a placeholder for a future user-presence button left over from the Tiny 2350 port. On the Tiny 2350 GP23 isn't connected to anything externally, so a pull-up there is harmless. On the XIAO, the internal pull-up drives GP23 to ~3.0 V, turning U7 on. With GP23 (and therefore U7) enabled but GP22 (NeoPixel data) floating, the WS2812 latches into an undefined state and draws transient currents on the 5V rail. Those transients propagate to VBUS, where the host's USB stack sees them as a brown-out and aborts enumeration.

The fix lives in the board profile, `crates/firmware/src/board/xiao_rp2350.rs` (`Board::setup`), which claims the pin as a push-pull output already driven low so that it never passes through a floating or high state during bring-up:

```rust
// NeoPixel power-gate -> start LOW (rail off).
let neopixel_power_off = pins.gpio23.into_push_pull_output_in_state(PinState::Low);
```

The pin is parked in the `Board` struct for the lifetime of the firmware (the output latch is set before the pad becomes an output, so a warm / RUN-pin reset cannot momentarily drive it high either). There's no GP22 init needed because U7 isolates the NeoPixel's V_DD entirely, so the WS2812 chip is unpowered and GP22's state is irrelevant.

## GPIO assignments

All assignments are made in the active board profile's `Board::setup` (`crates/firmware/src/board/<board>.rs`); `main.rs` only splits the pin set with `board::BoardPins::split(pins)` right after `hal::gpio::Pins::new` and hands the board its share. The C port's equivalents are the pin profiles in `c/firmware/src/board.c`, which copy these numbers.

### Tiny 2350 (`board_tiny2350`, default)

| GPIO  | Direction          | Function                                                                                |
| ---   | ---                | ---                                                                                     |
| GP18  | Push-pull output   | **Red LED** -- on while CTAP2 CBOR work is in flight                                     |
| GP19  | Push-pull output   | **Green LED** -- on during the post-WINK 1 s window, blinks during the UP-wait window   |
| GP20  | Push-pull output   | **Blue LED** -- heartbeat blink @ 500 ms while idle                                      |
| GP0   | Input, boot-probed pull | **Optional user-presence touch input** (external TTP223-style module or momentary switch; either polarity -- auto-detected at boot, verdict flashed green/red). The on-board **BOOT button on QSPI_SS is the primary presence button**, sampled at runtime. See "User-presence buttons" above. |

All three RGB-LED pins on the Tiny 2350 are active-low: drive **low** to light, drive **high** to extinguish. The firmware uses `set_low()` to turn an LED on and `set_high()` to turn it off, matching `embedded-hal::digital::OutputPin` semantics.

### Feitian RP2350 (`board_feitian_rp2350`)

| GPIO  | Direction          | Function                                                                                |
| ---   | ---                | ---                                                                                     |
| GP25  | Push-pull output   | **User LED** (green, **active-high** -- opposite polarity to the XIAO's GP25). Receives an OR of the R/G/B logical channels |
| QSPI_SS | (flash interface) | **BOOTSEL button** -- doubles as the user-presence button via runtime chip-select sampling (`board/bootsel.rs`); no GPIO setup involved |

Pi Pico 2 reference-design build (schematic `PICO2_G9_QE09_V1.0`): GP24 is the VBUS sense divider, GP29 the VSYS/3 sense, GP23 the SMPS power-save pin -- all per the reference design and untouched by the firmware. The firmware's constants address a 4 MiB window, but the die fitted to these Feitian samples is **2 MiB** (measured -- see docs/DFU.md; addresses past the end alias rather than fault). `FLASH_DEVINFO` OTP is unprogrammed, so `picotool erase -a` cannot size the chip -- use a range erase; see docs/FLASHING.md.

### Feitian RP2350 USB-C token (`board_feitian_rp2350_usbc`)

The Feitian RP2350 above, in a sealed USB-C security-key case. The Rust profile re-exports the Feitian RP2350's `Board` (same LED driver, same sampler) and differs only in its identity (`NAME = "Feitian RP2350 USB-C"`, USB product `Feitian USB-C PQC`, `pqf-board=feitian_rp2350_usbc`) and in `HAS_POWER_ON_BOOTSEL = false`. The C profile (`-DPQF_BOARD=feitian_rp2350_usbc`, pico-sdk `pico2`) likewise matches `feitian_rp2350` and declares 2 MiB of flash.

| GPIO  | Direction          | Function                                                                                |
| ---   | ---                | ---                                                                                     |
| GP25  | Push-pull output   | **User LED** (green, **active-high**, as the Feitian RP2350 -- assumed). Receives an OR of the R/G/B logical channels |
| QSPI_SS | (flash interface) | **Capacitive touch pad** -- the user-presence input, read by runtime chip-select sampling (`board/bootsel.rs`, `bootsel.c`) -- confirmed on one production token |

What is known, from Feitian's description, the one USB-C sample seen, and the first production token (2026-10-02, [TESTING.md](TESTING.md#the-first-production-usb-c-token-2026-10-02)):

- RP2350A with its QSPI flash on the Pico 2 reference design, a USB-C plug, one LED, and a **capacitive touch pad** as its only input -- **no button, no RESET, no display**, and no known debug connector.
- **No working power-on BOOTSEL**: holding the pad while plugging in does not enter the ROM bootloader. Only runtime touch registered (observed on the sample; not retried on the production token).
- Tokens arrive with **blank flash** (confirmed on the production token: in boot mode by itself, nothing in flash, no OTP boot-flag row set), so the boot ROM presents the `RP2350` drive by itself on first plug-in -- the only time the token enters BOOTSEL without being asked by firmware.
- The pad sits on QSPI_SS and is read by the same sampler as the USB-A board's button (confirmed: register and login through the pad on the production token).
- The flash die is 2 MiB (measured on the production token), as the C port declares; the Rust port uses the same address window as the USB-A Feitian, which is harmless on the smaller die. Do not program `FLASH_DEVINFO` to "fix" either.

Still assumed, **not yet measured on a production token**:

- The LED is on GP25, active-high, as on the USB-A board.
- Whether the SWD pads are reachable.

The consequence: with no power-on BOOTSEL, the host-issued `CTAPHID_CMD_REBOOT` is the token's only way back into the bootloader, so on this board it is **never gated on a touch** -- by the board profile, in both ports, with no build option involved. FIDO presence still needs the pad. If a later batch wires the pad differently, logins time out but the token stays reflashable. What still makes a token unflashable is the wrong image (one built for another board, whose reboot waits for a press), or one that hangs before USB; which is why it is flashed only with `tools/flash-usbc.sh`, per [the USB-C token section of FLASHING.md](FLASHING.md#the-feitian-usb-c-token) (its [open questions](FLASHING.md#what-is-not-yet-known-about-this-token) list what is still to be measured).

### XIAO RP2350 (`board_xiao_rp2350`)

| GPIO  | Direction          | Function                                                                                |
| ---   | ---                | ---                                                                                     |
| GP25  | Push-pull output   | **User LED** (dual red/yellow, active-low). Receives an OR of the R/G/B logical channels -- see [LED state machine](#led-state-machine) below |
| GP23  | Push-pull output   | NeoPixel power-enable, **driven LOW**. Don't touch this pin. See "GP23 quirk" above.   |

The XIAO has a single physical LED, so the three logical channels (`r_on`/`g_on`/`b_on`) all OR-merge onto GP25 via a `state: u8` bitfield inside the `leds::Leds` struct. The colour cue is lost -- you can't tell crypto-in-flight (red) from UP-wait (green flicker) from idle (blue) -- but the "device is doing something" signal is preserved. Solid orange = busy; slow blink = idle; fast blink = waiting for user presence.

### Waveshare RP2350-LCD-1.47 (-A / -B / -B-M) (`board_waveshare_rp2350_lcd_1_47`)

| GPIO  | Direction          | Function                                                                                                                                |
| ---   | ---                | ---                                                                                                                                     |
| GP16  | Push-pull output   | LCD_DC (data/command select)                                                                                                            |
| GP17  | Push-pull output   | LCD_CS (software-toggled chip-select)                                                                                                   |
| GP18  | SPI0 SCK alt-func  | LCD_SCK                                                                                                                                 |
| GP19  | SPI0 TX alt-func   | LCD_MOSI                                                                                                                                |
| GP20  | Push-pull output   | LCD_RST                                                                                                                                 |
| GP21  | Push-pull output   | LCD backlight                                                                                                                           |
| GP23  | Push-pull output   | WS2812 NeoPixel data line, **driven LOW** to hold the LED chain in its reset / no-data state. The board's RGB lamps stay dark.         |
| all others | Untouched     | micro-SD and any other peripheral pins are left at their boot-time defaults (high-Z inputs); the SD slot is electrically idle.         |

The three variants share this GPIO map; `-B` is the bare board with USB-C, `-B-M` the same with soldered headers, and the earlier `-A` has a micro-USB connector instead. The firmware drives the **1.47" ST7789V2 LCD as a live device-stats panel** (firmware version, board name, algorithm summary, USB serial, PIN state + retries, resident-credential count, uptime, most recent CTAP operation) -- see `crates/firmware/src/board/waveshare_rp2350_lcd_1_47/lcd.rs`. The board's RGB lamps remain a WS2812 NeoPixel chain that needs PIO-driven 800 kHz serial data (T0H ~ 350 ns, T1H ~ 700 ns per the WS2812B datasheet); driving them is a ~150 LOC future task, so the LED-channel API on this board stays a no-op and the LCD is the status surface.

The board's BOOT button is on QSPI_SS and this profile doesn't sample it (unlike the Feitian profile -- adoption is possible, see `board/bootsel.rs`). RST is a hard chip-reset, not a user-input GPIO. So `Board::user_present` always returns `false` and the firmware's `WaitForUp` auto-confirms after the LED/keepalive stub (same as the XIAO and Spotpear).

### Spotpear RP2350-LCD-1.28 (`board_spotpear_rp2350_lcd_1_28`)

| GPIO  | Direction          | Function                                                                                |
| ---   | ---                | ---                                                                                     |
| GP8   | Push-pull output   | LCD_DC                                                                                  |
| GP9   | Push-pull output   | LCD_CS                                                                                  |
| GP10  | SPI1 SCK alt-func  | LCD_SCK                                                                                 |
| GP11  | SPI1 TX alt-func   | LCD_MOSI                                                                                |
| GP12  | Push-pull output   | LCD_RST                                                                                 |
| GP25  | Push-pull output   | LCD backlight                                                                           |
| GP6 / GP7 | Untouched      | QMI8658 IMU I^2C -- left at boot-time high-Z; the IMU stays unaddressed                   |
| GP23 / GP24 | Untouched    | IMU INT1 / INT2 -- left at boot-time defaults                                            |
| GP29  | Untouched          | Battery ADC                                                                             |

Round 1.28" 240x240 GC9A01 IPS panel driven as a **centred stats panel** -- text is confined to the inscribed square so nothing clips at the circular edge (`crates/firmware/src/board/spotpear_rp2350_lcd_1_28/lcd.rs`). No discrete user LED; no firmware-readable button in this profile (RST is hard reset, BOOT is on QSPI_SS and not sampled here), so `Board::user_present` returns `false` and `WaitForUp` auto-confirms, like the XIAO and Waveshare.

## LED state machine

What the indicator means while the firmware is running:

```
   blue (steady blink, 500 ms on / 500 ms off)
       device idle, USB enumerated, ready for a CTAP HID request

   red on
       a CTAP2 CBOR command is being processed
       (parsing -> key derivation -> flash writes -> response build).
       The heartbeat pauses while a command runs, so blue stays in
       whatever state it was in: purple (red + blue) if it was on

   green fast blink (100 ms on / 100 ms off), red and blue off
       waiting for a touch, on boards with a presence input. The
       gate turns red and blue off so that on the single-LED boards,
       where all three channels light the same LED, the blink is
       the only thing the LED shows

   green flash (1 second)
       wink -- relying party asked us to identify ourselves
       (CTAPHID CMD_WINK, advertised in the INIT capabilities byte)

   no LED activity at all
       device hung -- power-cycle. The `panic-halt` panic handler
       just stops the CPU and doesn't relight any LED. If the host's
       USB tree shows the device disappearing, this is what happened.
```

The blue heartbeat doubles as a basic *is-the-CPU-still-running* indicator. If you ever see the device enumerated but with the blue LED stuck on or off, the main loop has stopped and a reboot is the only recovery.

On the two LCD boards (Waveshare 1.47", Spotpear 1.28") there is no discrete status LED -- the stats panel is the liveness indicator instead: the uptime counter ticks once a second, and the "last operation" line updates on every CTAP command.

## BOOT button (QSPI_SS)

Used by the RP2350 boot ROM as the BOOTSEL signal: hold it while plugging in (or while tapping RESET) and the chip falls into the boot ROM's UF2 / picoboot mode instead of running our firmware. On every supported board that has one, the BOOT button is wired to **QSPI_SS**, the flash chip-select line -- a dedicated flash-interface pin, not a GPIO, so ordinary pin reads can't see it. The Feitian RP2350 USB-C token has no BOOT button; its touch pad sits on the same line (confirmed on one production token), but it does not trigger the boot ROM's power-on sensing.

Whether firmware can still use it depends on the board profile:

  - **Feitian RP2350** samples it at runtime via the chip-select
    float trick (`board/bootsel.rs` / `bootsel.c`) and uses it as the
    real CTAP user-presence button -- see "User-presence buttons" at
    the top of this document.
  - **Tiny 2350** reads its BOOT button the same way, and additionally
    an external GP0 touch input.
  - **Feitian RP2350 USB-C token** reads its touch pad through the same
    sampler (confirmed on one production token, 2026-10-02).
  - The other boards don't read it; their `WaitForUp` auto-confirms
    after the LED/keepalive window.

## USB descriptor

Set in `crates/firmware/src/main.rs` via `usb-device`'s `UsbDeviceBuilder`. Hosts find the token by its HID usage page, not by its vendor and product ids, so anything talking to a Yubikey / SoloKey / OpenSK device works against us out of the box; the ids themselves are placeholders.

| Field                    | Value                                                                                                              |
| ---                      | ---                                                                                                                |
| `idVendor`               | `0xcafe` -- TinyUSB's example vendor id, used by both ports and the bootloader. **A placeholder**: no vendor id is registered for this project. Replace it, and the product id, with your own allocation before shipping a product, and change `tools/udev/99-bruce.rules` to match |
| `idProduct`              | `0xF1D0` -- project-local product id, chosen to mirror the FIDO HID usage page (the TrustZone Non-secure image uses `0xF1DC` so it is never mistaken for production firmware) |
| `bcdDevice`              | Derived from `CARGO_PKG_VERSION` at compile time. `0.1.0` -> `0x0010`, `1.2.3` -> `0x0123`. Bump on each release.   |
| `iManufacturer`          | `"Bruce"`                                                                                                       |
| `iProduct`               | The board profile's `USB_PRODUCT`: `"Tiny 2350 PQC"`, `"XIAO RP2350 PQC"`, `"Feitian RP2350 PQC"`, `"Feitian USB-C PQC"`, `"RP2350-LCD-1.47 PQC"` or `"RP2350-LCD-1.28 PQC"`. The firmware appends ` QRNG` when a quantum RNG answered at boot and ` 1CORE` on a `single_core` build, so a host can tell what it is talking to. |
| `iSerialNumber`          | **Random 8-hex-char string regenerated on each boot** from the entropy picker, so the QRNG when one is attached and the on-chip TRNG otherwise (e.g. `"9798D20A"`). See note below. |
| Max packet size 0        | 64 bytes                                                                                                           |
| Interface class          | HID                                                                                                                |
| Usage page (HID)         | `0xF1D0` (FIDO Alliance)                                                                                           |
| Usage                    | `0x01` (U2F Authenticator Device)                                                                                  |
| Endpoints                | 1x interrupt-IN (64 B, 1 ms polling) + 1x interrupt-OUT (64 B, 1 ms polling)                                       |

> **C port.** The C firmware builds its own composite descriptor
> (`c/firmware/src/usb_descriptors.c`): the same `cafe:f1d0`, a
> CDC ACM banner port on interfaces 0+1 and the FIDO HID on interface 2.
> It carries the same per-boot random serial for the same reason (below).
> A **debug build** (`-DPQF_GDB_STUB=ON`) appends a *second* CDC pair on
> interfaces 3+4 carrying the on-token GDB stub, so such a device
> enumerates two ttys -- the FIDO HID interface number and wire behaviour
> are unchanged either way. See
> [`GDB_DEBUG.md`](GDB_DEBUG.md#find-the-port).

### Why a random serial per boot

The original hardcoded `"0001"` serial made every reboot of every device look identical to macOS's IOKit HID layer. Combined with the ~2 s disconnect/reconnect window after `picotool load -x`, macOS would sometimes serve Chrome's WebAuthn USB transport stale CTAPHID capability state from before the flash. Symptoms ranged from "Chrome doesn't show my device" to subtly wrong capability bits being used post-flash.

The fix (`e718a05`): generate a fresh 8-hex-char serial from the TRNG on each boot, format as an ASCII string, `Box::leak` into a `'static &str` for the `UsbDeviceBuilder`. macOS now treats every reboot as a fresh device-attach and re-queries getInfo cleanly. The leak is ~10 bytes permanent heap, dwarfed by our 256 KiB heap allocation.

FIDO2 RPs identify the authenticator by **AAGUID** (hardcoded in firmware, doesn't change) and by **credential ID** (master-key-derived, doesn't change without a wipe), so randomizing the USB serial has no protocol-level effect on credential continuity. It's purely USB-stack hygiene.

The HID report descriptor is hand-rolled in `crates/firmware/src/fido_hid.rs` -- the `usbd-hid` macro doesn't accommodate FIDO's vendor-defined data array nicely, so the firmware emits the descriptor bytes directly:

```
Usage Page (0xF1D0)        06 D0 F1
Usage (0x01)               09 01
Collection (Application)   A1 01
  Usage (0x20)             09 20  // U2F HID Report
  Logical Min 0            15 00
  Logical Max 0xFF         26 FF 00
  Report Size 8            75 08
  Report Count 64          95 40
  Input  (Data, Variable, Absolute)  81 02
  Usage (0x21)             09 21  // U2F HID Output
  Logical Min 0            15 00
  Logical Max 0xFF         26 FF 00
  Report Size 8            75 08
  Report Count 64          95 40
  Output (Data, Variable, Absolute)  91 02
End Collection             C0
```

## TRNG (`crates/firmware/src/trng.rs`)

The RP2350 has a ring-oscillator TRNG in its random number generator block. The firmware uses it directly without an upstream `rand` backend -- `crates/firmware/src/trng.rs` wraps it as a `rand_core::RngCore + CryptoRng`.

| Parameter                | Value / behaviour                                                                                                          |
| ---                      | ---                                                                                                                        |
| Entropy source           | Ring oscillator, length-3 (the longest of 4 selectable lengths -- most entropy / cycle)                                     |
| Sample count             | `0x1000` samples per collection (conservative; gives ~100 us / collection at 125 MHz)                                       |
| Output buffer            | 6 x 32-bit `ehr_data0..5` registers -- 24 bytes per polled cycle                                                              |
| Polling                  | Spin on `rng_isr` bit 0 (`ehr_valid`); clear via `rng_icr` write                                                            |
| Initialisation           | One-time configuration in `Trng::new` -- enables the RNG block via the resets controller, picks the ring-osc length, kicks  |
| Drained on Reset (CTAP2) | Yes -- `wipe_all(trng)` consumes fresh bytes to rotate the per-device master keys                                            |

Randomness reaches the dispatch as `&mut impl CryptoRngCore`, and what `main.rs` passes is `entropy::Entropy` -- the TRNG with the optional QRNG below in front of it. Core 1's signing path doesn't need fresh randomness (the hybrid scheme is deterministic given the seed + msg), so the sources only spin on core 0 during request parsing, credential generation, IV generation for credentialID encryption, and PIN-token regeneration.

## QRNG over I2C (optional)

A **quantum random number generator** on the I2C bus is the preferred entropy source in both ports whenever one is attached. Nothing attached means the firmware behaves exactly as before; the probe costs microseconds on an empty bus.

| Parameter        | Value / behaviour |
| ---              | --- |
| Wiring (default) | **The Tiny 2350's QW/ST connector: I2C0, SDA GP12, SCL GP13**, 3V3, GND. The 4-pin cable has no PD line; the breakout idles PD high itself. The breakout header (A0/A1 = GP26/GP27 = I2C1, PD on any free GPIO) works in the C port via `-DPQF_QRNG_I2C=`, `_SDA=`, `_SCL=`, `_PD=` (`-1` = not wired), `_BAUD=`; `-DPQF_QRNG=OFF` compiles it out. Rust: fixed to the QW/ST wiring (`crates/firmware/src/qrng.rs`, `hw`). **Spotpear RP2350-LCD-1.28:** GP12 is its LCD reset, so the C option defaults OFF there and the Rust board split hands out no QRNG pins -- TRNG only unless re-wired. |
| Bus              | 100 kHz (the rate the source was qualified at; the part allows 50-400 kHz), 7-bit address `0x37` |
| Protocol         | Status register `0x10` (`0x00` = ready); packet burst read at `0x12` = header `0xA2`, health byte (low nibble must be 0), 16 entropy bytes. Fresh packet every ~500 us |
| Probe            | At boot, before anything mints a key: a status read (an absent chip NAKs in us), then a PD power-cycle for a clean calibration (a no-op when PD is not wired, as on QW/ST), then wait for ready (bounded, <= ~100 ms). A chip that ACKs but never reads ready is treated as absent |
| Conditioning     | **SHA-256 over 64 raw bytes -> 32 out.** The part has no DRBG inside and claims >= 7.0 bits of min-entropy per byte; its raw stream is measurably biased. No raw byte is ever handed on; header and health bytes never reach the hash |
| Failure policy   | Bad header / health flag -> packet dropped, next one read. Bus error -> bounded retries. A 64-byte draw that cannot complete returns the request short and the **TRNG completes it** (the conditioned bytes that did arrive are kept). After a failed draw one status read decides: a chip that no longer answers (unplugged; an unpowered breakout also drags the lines low) is **written off on that same request**, bus released, TRNG only until reboot; a chip that still answers is written off after eight such requests in a row |
| Bounded          | Every transfer carries a 20 ms deadline; SDA/SCL idle levels are checked and a stuck bus is clocked out (nine SCL pulses + STOP) before the controller claims the pins. The Rust transport drives the I2C block through the PAC rather than the HAL for exactly this reason |
| Instruction sets | Arm, pure RISC-V (the timeout I2C calls poll the timer, no alarms) and mixed. In the **mixed** build the RISC-V blob cannot reach the bus, so core 0 puts 32 bytes of its own QRNG-first entropy into the mailbox with every request and the blob's `RAND_bytes` serves `SHA-256(host entropy || TRNG block || counter)` |
| Observability    | Both ports: the vendor `CMD_RNG_STATUS` command reports the live source (TRNG / QRNG / QRNG lost since boot) and the counters; `make -C c/hid rng && ./c/hid/rng` prints it with a timed draw. C additionally names the source and wiring on the CDC boot banner and carries `[rng] src= qrng= fallback= pkts= hdr= hlth= bus= short=` on the heartbeat. Rust also appends ` QRNG` to the USB product string when the chip was found at boot (fixed at enumeration, so it does not follow a later unplug -- the status command does) |
| Not covered      | The TrustZone Secure world (`crates/fw-secure`) still mints from its own TRNG copy. Everything in the two main firmware images, down to the per-boot USB serial, goes through the picker |

Host coverage: `crates/firmware-hosttest/tests/real_qrng.rs` and `c/firmware/test/test_qrng.c` drive the real drivers against a scripted bus; all six port x instruction-set images were validated on a Tiny 2350 with the chip on QW/ST on 2026-09-15 (see [TESTING.md](TESTING.md#the-qrng-driver-and-the-entropy-picker)).

## Memory map

From `crates/firmware/memory.x` (the same 4 MiB flash window is used on every board, including the 16 MiB Waveshare, so the flash-store offsets are identical everywhere):

```
MEMORY {
    FLASH : ORIGIN = 0x10000000, LENGTH = 4096K   /* QSPI flash, XIP */
    RAM   : ORIGIN = 0x20000000, LENGTH = 512K    /* striped SRAM, banks 0-7 (cortex-m-rt expects the name RAM) */
    SRAM8 : ORIGIN = 0x20080000, LENGTH = 4K      /* direct-mapped bank 8 */
    SRAM9 : ORIGIN = 0x20081000, LENGTH = 4K      /* direct-mapped bank 9 */
}
```

A few constants the firmware imports against this map:

| Region                                  | Constant in code              | Notes                                                                                                                        |
| ---                                     | ---                           | ---                                                                                                                          |
| Flash credential store sector           | `flash_store::STORE_OFFSET = 0x003FF000` | Last 4 KiB sector of the QSPI. Read via XIP at `0x103FF000`; written via the boot-ROM flash routines (see ARCHITECTURE.md). |
| Heap (core 0 + core 1)                  | `HEAP_SIZE = 256 KiB`          | `embedded-alloc::LlffHeap` initialised once on boot. Static byte array in `.bss`.                                            |
| Core 1 stack                            | `core1_signer::CORE1_STACK_WORDS = 64 KiB / 4` | `static rp235x_hal::multicore::Stack<...>` in `.bss`. ML-DSA-87 worst-case high-water mark is ~50 KiB.                       |

Linker sections we add on top of `cortex-m-rt`'s defaults:

- `.start_block` -- at the very start of flash, holds the RP2350 `IMAGE_DEF` ARM-Secure metadata block. Without this the boot ROM rejects the image.
- `.bi_entries` -- array of `EntryAddr`s for `picotool info`. Holds the program name (from `Cargo.toml`), version, description, build attribute, and the three `pqf-*` program features.
- `.end_block` -- placeholder at end of `.text` for a future signature block.

## Picotool metadata

`crates/firmware/src/main.rs` exports a `PICOTOOL_ENTRIES` array, so `picotool info` over USB (or against the on-flash binary) yields:

```
$ picotool info
Program Information
 name:          Bruce
 version:       0.1.0
 description:   Hybrid PQC FIDO2 authenticator on RP2350 (Pimoroni Tiny 2350)
 features:      pqf-board=tiny2350
                pqf-reboot=touch
                pqf-fido-up=touch
 binary start:  0x10000000
 target chip:   RP2350
 image type:    ARM Secure
```

The description comes from the active board profile's `BI_DESCRIPTION` and names the board. The three features say the same in a form a script can check before flashing: `pqf-board=` is the profile's `BI_BOARD`, and `pqf-reboot=touch|no-touch` and `pqf-fido-up=touch|auto` are derived from the same consts the code is built from (`HAS_USER_BUTTON`, `HAS_POWER_ON_BOOTSEL`, `reboot_no_up`, `test_no_user_button`), so what picotool prints is what the image does. The C port carries the same three features in its own binary-info block (`src/main.c`, from `PQF_BOARD` and `src/board.h`); the URL it records is the `PQF_PROGRAM_URL` CMake option, see [BUILD.md](BUILD.md#cmake-options). The values and why they matter for the USB-C token are in [BUILD.md](BUILD.md#identifying-an-image-before-flashing-it).

The name, version, description and build-attribute entries are produced by the `rp_cargo_bin_name!()`, `rp_cargo_version!()`, `rp_program_description!()` and `rp_program_build_attribute!()` macros from `rp235x-hal::binary_info`.

## Why no boot stage 2?

Pre-RP2350 (Pi Pico, etc.) needed a 256-byte boot stage 2 to configure the QSPI controller before XIP would work. RP2350 keeps the boot ROM smarter and configures XIP itself from the QSPI's status registers. The firmware just drops its `IMAGE_DEF` block at offset 0 and the ROM does the rest -- see the comments at the top of `Cargo.toml` for the historical context (`#![no_main]`, no `boot2` section).

## Power and current

The Tiny 2350 draws roughly 35 mA from VBUS when idle (USB enumerated, blue LED blinking) and around 55 mA during a hybrid sign on core 1 -- both well within USB 2.0's 100 mA spec. Cold-boot inrush is brief; no external bulk capacitor needed.

## Hardware in summary

You need exactly one of the six boards (the Pimoroni Tiny 2350 is the default and the reference) plus a data-capable USB cable. There's nothing to wire, nothing to solder, no jumpers to set; the GP0 touch pad on the Tiny 2350 and the QRNG breakout are optional extras. Hold BOOT + plug in (or BOOT + tap RESET on a board that has one) to enter BOOTSEL; release BOOT and the chip boots normally back into the firmware. The per-board recipes are in [FLASHING.md](FLASHING.md). The Feitian RP2350 USB-C token has no BOOT button and no physical recipe; it is flashed only as described in [the USB-C token section of FLASHING.md](FLASHING.md#the-feitian-usb-c-token).
