// Copyright 2026 Cryptsoft Pty Ltd
// SPDX-License-Identifier: Apache-2.0

//! The `CTAPHID_CMD_REBOOT` presence policy, by truth table.
//!
//! `reboot_needs_presence` decides whether the host-issued reboot waits
//! for a touch. On the sealed Feitian USB-C token that reboot is the
//! only way back into the bootloader, so a wrong `true` there is not a
//! bug report, it is a token that can never be reflashed. The function
//! is four booleans in and one out; every row is enumerated here, and
//! the six board profiles' inputs are read from the board modules
//! themselves so the table cannot drift from what ships.

use pqf_firmware_hosttest::reboot_policy::reboot_needs_presence;

/// One board module's source. The modules themselves cannot compile on
/// the host (they own HAL pin types), so their policy constants are
/// read from the text; the line shape is the one the interface contract
/// in `board/mod.rs` prescribes, `pub const NAME: type = value;`.
struct Profile {
    id: &'static str,
    src: &'static str,
}

const BOARDS: [Profile; 6] = [
    Profile {
        id: "tiny2350",
        src: include_str!("../../firmware/src/board/tiny2350.rs"),
    },
    Profile {
        id: "xiao_rp2350",
        src: include_str!("../../firmware/src/board/xiao_rp2350.rs"),
    },
    Profile {
        id: "feitian_rp2350",
        src: include_str!("../../firmware/src/board/feitian_rp2350.rs"),
    },
    Profile {
        id: "feitian_rp2350_usbc",
        src: include_str!("../../firmware/src/board/feitian_rp2350_usbc.rs"),
    },
    Profile {
        id: "waveshare_rp2350_lcd_1_47",
        src: include_str!("../../firmware/src/board/waveshare_rp2350_lcd_1_47/mod.rs"),
    },
    Profile {
        id: "spotpear_rp2350_lcd_1_28",
        src: include_str!("../../firmware/src/board/spotpear_rp2350_lcd_1_28/mod.rs"),
    },
];

fn board(id: &str) -> &'static Profile {
    BOARDS
        .iter()
        .find(|p| p.id == id)
        .unwrap_or_else(|| panic!("no board profile {id} in the table"))
}

/// The value of `pub const <name>: bool = ...;` in a board module.
fn const_bool(p: &Profile, name: &str) -> bool {
    let prefix = format!("pub const {name}: bool = ");
    let line = p
        .src
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with(&prefix))
        .unwrap_or_else(|| {
            panic!(
                "board {}: no `{prefix}...;` line -- every board module must \
                 declare it (board/mod.rs, interface contract)",
                p.id
            )
        });
    match line[prefix.len()..].trim_end_matches(';') {
        "true" => true,
        "false" => false,
        other => panic!("board {}: `{name}` is `{other}`, not a bool literal", p.id),
    }
}

/// The value of `pub const <name>: &CStr = c"...";` in a board module.
/// The literal may sit on the next line, where rustfmt puts one that
/// does not fit beside its name.
fn const_cstr(p: &Profile, name: &str) -> &'static str {
    let prefix = format!("pub const {name}: &CStr =");
    let at = p
        .src
        .find(&prefix)
        .unwrap_or_else(|| panic!("board {}: no `{prefix} c\"...\";` item", p.id));
    let rest = p.src[at + prefix.len()..]
        .trim_start()
        .strip_prefix("c\"")
        .unwrap_or_else(|| panic!("board {}: `{name}` is not a c\"...\" literal", p.id));
    let end = rest
        .find('"')
        .unwrap_or_else(|| panic!("board {}: `{name}` literal is not closed", p.id));
    &rest[..end]
}

/// A board's default build: its two facts, no feature overrides.
fn default_build(p: &Profile) -> bool {
    reboot_needs_presence(
        const_bool(p, "HAS_USER_BUTTON"),
        const_bool(p, "HAS_POWER_ON_BOOTSEL"),
        false,
        false,
    )
}

/// Every input combination, spelled out rather than recomputed: the
/// function is one expression, and a test that restated it would pass
/// whatever it said. Columns: has_user_button, has_power_on_bootsel,
/// reboot_no_up, test_no_user_button -> needs presence.
const TABLE: [(bool, bool, bool, bool, bool); 16] = [
    (false, false, false, false, false),
    (false, false, false, true, false),
    (false, false, true, false, false),
    (false, false, true, true, false),
    (false, true, false, false, false),
    (false, true, false, true, false),
    (false, true, true, false, false),
    (false, true, true, true, false),
    (true, false, false, false, false),
    (true, false, false, true, false),
    (true, false, true, false, false),
    (true, false, true, true, false),
    (true, true, false, false, true),
    (true, true, false, true, false),
    (true, true, true, false, false),
    (true, true, true, true, false),
];

#[test]
fn the_full_truth_table() {
    for (button, power_on_bootsel, no_up, test_gate, want) in TABLE {
        assert_eq!(
            reboot_needs_presence(button, power_on_bootsel, no_up, test_gate),
            want,
            "button={button} power_on_bootsel={power_on_bootsel} \
             reboot_no_up={no_up} test_no_user_button={test_gate}"
        );
    }
}

#[test]
fn exactly_one_row_needs_a_touch() {
    // A button the owner can press, a bootloader the owner can still
    // reach without it, and neither override. Anything else and the
    // reboot confirms at once.
    let rows_needing_presence = TABLE.iter().filter(|r| r.4).count();
    assert_eq!(rows_needing_presence, 1);
    assert!(reboot_needs_presence(true, true, false, false));
}

/// What each board's default image does -- the table docs/BUILD.md
/// ("Axis 5") publishes. The board facts behind it are read from the
/// modules, so a board-module change that would falsify that table
/// fails here rather than on a token.
#[test]
fn every_board_default_build_gates_as_documented() {
    let expected = [
        ("tiny2350", true),
        ("xiao_rp2350", false),
        ("feitian_rp2350", true),
        ("feitian_rp2350_usbc", false),
        ("waveshare_rp2350_lcd_1_47", false),
        ("spotpear_rp2350_lcd_1_28", false),
    ];
    assert_eq!(
        expected.len(),
        BOARDS.len(),
        "a board is missing from this table"
    );
    for (id, want) in expected {
        assert_eq!(
            default_build(board(id)),
            want,
            "{id}: default build should {}gate CMD_REBOOT on a touch",
            if want { "" } else { "NOT " }
        );
    }
}

/// The two facts per board, as the profiles declare them. Flipping the
/// USB-C token's `HAS_POWER_ON_BOOTSEL` to `true` would turn the reboot
/// gate back on for a token that has no other way into the bootloader;
/// that is the change this test exists to catch.
#[test]
fn the_board_facts_are_what_the_profiles_declare() {
    // (id, HAS_USER_BUTTON, HAS_POWER_ON_BOOTSEL)
    let facts = [
        ("tiny2350", true, true),
        ("xiao_rp2350", false, true),
        ("feitian_rp2350", true, true),
        ("feitian_rp2350_usbc", true, false),
        ("waveshare_rp2350_lcd_1_47", false, true),
        ("spotpear_rp2350_lcd_1_28", false, true),
    ];
    for (id, button, power_on_bootsel) in facts {
        let p = board(id);
        assert_eq!(
            const_bool(p, "HAS_USER_BUTTON"),
            button,
            "{id}: HAS_USER_BUTTON"
        );
        assert_eq!(
            const_bool(p, "HAS_POWER_ON_BOOTSEL"),
            power_on_bootsel,
            "{id}: HAS_POWER_ON_BOOTSEL -- if this is the USB-C token, `true` \
             makes CMD_REBOOT wait for a touch on a token whose ONLY way back \
             into the bootloader is CMD_REBOOT"
        );
    }
}

#[test]
fn the_usbc_token_needs_no_touch_however_the_pad_turns_out() {
    // `HAS_USER_BUTTON` on the USB-C token began as a working assumption
    // from one sample (confirmed on the first production token on
    // 2026-10-02). Whichever way a later batch turns out, the reboot
    // must not depend on it -- that is what the second input is for.
    for pad_readable in [true, false] {
        assert!(!reboot_needs_presence(pad_readable, false, false, false));
    }
    let usbc = board("feitian_rp2350_usbc");
    assert!(!const_bool(usbc, "HAS_POWER_ON_BOOTSEL"));
    assert!(!default_build(usbc));
}

#[test]
fn reboot_no_up_removes_the_gate_on_the_button_boards_and_changes_nothing_elsewhere() {
    for p in BOARDS.iter() {
        let button = const_bool(p, "HAS_USER_BUTTON");
        let power_on_bootsel = const_bool(p, "HAS_POWER_ON_BOOTSEL");
        assert!(
            !reboot_needs_presence(button, power_on_bootsel, true, false),
            "{}: reboot_no_up must remove the gate",
            p.id
        );
    }
    // ...and it is the button boards on which it makes a difference.
    for id in ["tiny2350", "feitian_rp2350"] {
        assert!(default_build(board(id)), "{id} is gated by default");
    }
}

#[test]
fn test_no_user_button_removes_the_gate_everywhere() {
    for p in BOARDS.iter() {
        let button = const_bool(p, "HAS_USER_BUTTON");
        let power_on_bootsel = const_bool(p, "HAS_POWER_ON_BOOTSEL");
        assert!(
            !reboot_needs_presence(button, power_on_bootsel, false, true),
            "{}: test_no_user_button must remove the gate",
            p.id
        );
    }
}

/// `picotool info -a` identifies an image by `pqf-board=<id>`, where the
/// id is the cargo feature name minus `board_`. The spelling is a
/// contract with docs/BUILD.md and the flashing tools.
#[test]
fn the_picotool_board_ids_match_the_feature_names() {
    let cargo_toml = include_str!("../../firmware/Cargo.toml");
    for p in BOARDS.iter() {
        assert!(
            cargo_toml
                .lines()
                .any(|l| l.starts_with(&format!("board_{} = ", p.id))),
            "{}: no `board_{} = ...` feature in crates/firmware/Cargo.toml",
            p.id,
            p.id
        );
        assert_eq!(
            const_cstr(p, "BI_BOARD"),
            format!("pqf-board={}", p.id),
            "{}: BI_BOARD",
            p.id
        );
        let description = const_cstr(p, "BI_DESCRIPTION");
        assert!(
            description.starts_with("Hybrid PQC FIDO2 authenticator on RP2350 (")
                && description.ends_with(')'),
            "{}: BI_DESCRIPTION should name the board in the shared form, not {description:?}",
            p.id
        );
    }
}

/// The two policy markers main.rs selects from. `tools/flash-usbc.sh`
/// refuses any image without `pqf-reboot=no-touch`, so a respelling
/// here would not fail a build -- it would fail every USB-C flash, or
/// worse, a tool that matched loosely would stop telling the two apart.
#[test]
fn the_policy_markers_are_spelled_as_the_tools_expect() {
    let main_rs = include_str!("../../firmware/src/main.rs");
    for marker in [
        "c\"pqf-reboot=touch\"",
        "c\"pqf-reboot=no-touch\"",
        "c\"pqf-fido-up=touch\"",
        "c\"pqf-fido-up=auto\"",
    ] {
        assert!(main_rs.contains(marker), "main.rs no longer emits {marker}");
    }
}
