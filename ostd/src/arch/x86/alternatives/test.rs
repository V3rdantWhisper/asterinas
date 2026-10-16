// SPDX-License-Identifier: MPL-2.0

use core::{
    arch::{asm, global_asm},
    sync::atomic::AtomicBool,
};

use super::{
    AlternativeId, AlternativeUpdateError, AlternativesError, BOOT_PATCHING_ATTEMPTED,
    alternative_macros::{alternative, alternative_asm_template},
    condition,
};
use crate::{arch::alternatives, prelude::*};

global_asm!(
    include_str!("alternative_macros.S"),
    include_str!("test.S"),
    ".purgem OSTD_ALTERNATIVE",
    replace_add_condition_id = const AlternativeId::Always.as_raw(),
);

unsafe extern "C" {
    fn ostd_alt_test_asm_add(value: u64) -> u64;
    fn ostd_alt_test_asm_add_twice(value: u64) -> u64;
}

#[inline(never)]
fn alt_test_rust_add(mut value: u64) -> u64 {
    // SAFETY: Both variants only modify the declared RAX and flags. The site is
    // only called before or after the BSP's commit, never from an exception.
    unsafe {
        asm!(
            alternative_asm_template!("add rax, 1", "add rax, 42"),
            alt_condition_id = const AlternativeId::Always.as_raw(),
            inout("rax") value,
            options(nostack),
        );
    }
    value
}

#[inline(never)]
fn alt_test_rust_add_disabled(mut value: u64) -> u64 {
    // SAFETY: The variants only modify the declared RAX and flags.
    unsafe {
        asm!(
            alternative_asm_template!("add rax, 1", "add rax, 42"),
            alt_condition_id = const AlternativeId::TestDisabled.as_raw(),
            inout("rax") value,
            options(nostack),
        );
    }
    value
}

#[inline(never)]
fn alt_test_rust_add_enabled(mut value: u64) -> u64 {
    // SAFETY: Both variants only modify the declared RAX and flags. The test
    // policy selects the replacement before any instruction is patched.
    unsafe {
        asm!(
            alternative_asm_template!("add rax, 1", "add rax, 42"),
            alt_condition_id = const AlternativeId::TestEnabled.as_raw(),
            inout("rax") value,
            options(nostack),
        );
    }
    value
}

#[inline(never)]
fn alt_test_rust_add_twice(mut value: u64) -> u64 {
    // SAFETY: Both slots only modify RAX and flags. The extra NOPs exercise
    // a growing and a shrinking replacement in adjacent, differently sized slots.
    unsafe {
        asm!(
            alternative_asm_template!("add rax, 1", "add rax, 42; nop; nop"),
            alternative_asm_template!("add rax, 1; nop", "add rax, 42"),
            alt_condition_id = const AlternativeId::Always.as_raw(),
            inout("rax") value,
            options(nostack),
        );
    }
    value
}

#[inline(never)]
fn alt_test_rust_insert_lfence() {
    // SAFETY: LFENCE and NOP change neither registers nor flags. The asm remains
    // a compiler memory barrier regardless of the selected variant.
    unsafe {
        alternative!("", "lfence", AlternativeId::Always);
    }
}

#[inline(never)]
fn alt_test_rust_remove_lfence() {
    // SAFETY: This fence is only a test site, not a required synchronization
    // point. Both variants preserve registers, flags, and the stack.
    unsafe {
        alternative!("lfence", "", AlternativeId::Always);
    }
}

pub(super) fn check_original_instructions() {
    assert_eq!(alt_test_rust_add(10), 11);
    assert_eq!(alt_test_rust_add_disabled(10), 11);
    assert_eq!(alt_test_rust_add_enabled(10), 11);
    assert_eq!(alt_test_rust_add_twice(10), 12);
    // SAFETY: This leaf follows the SysV ABI and only adds an integer constant.
    assert_eq!(unsafe { ostd_alt_test_asm_add(10) }, 11);
    // SAFETY: This leaf follows the same ABI and modifies only RAX and flags.
    assert_eq!(unsafe { ostd_alt_test_asm_add_twice(10) }, 12);
    alt_test_rust_insert_lfence();
    alt_test_rust_remove_lfence();
}

pub(super) fn configure_conditions() {
    // Separate calls model policy owners applying their decisions independently.
    alternatives::enable_condition(AlternativeId::TestEnabled).unwrap();
    alternatives::enable_condition(AlternativeId::TestDisabled).unwrap();
    alternatives::disable_condition(AlternativeId::TestDisabled).unwrap();
}

#[ktest]
fn patched_instructions_execute() {
    assert_eq!(alt_test_rust_add(10), 52);
    assert_eq!(alt_test_rust_add_disabled(10), 11);
    assert_eq!(alt_test_rust_add_enabled(10), 52);
    assert_eq!(alt_test_rust_add_twice(10), 94);
    // SAFETY: Patching retains the same SysV ABI and leaf-function contract.
    assert_eq!(unsafe { ostd_alt_test_asm_add(10) }, 52);
    // SAFETY: Both slots retain the leaf's SysV ABI and arithmetic contract.
    assert_eq!(unsafe { ostd_alt_test_asm_add_twice(10) }, 94);
    alt_test_rust_insert_lfence();
    alt_test_rust_remove_lfence();
}

#[ktest]
fn frozen_conditions_reject_updates() {
    assert_eq!(
        alternatives::enable_condition(AlternativeId::TestDisabled),
        Err(AlternativeUpdateError::Frozen)
    );
    assert_eq!(
        alternatives::disable_condition(AlternativeId::TestEnabled),
        Err(AlternativeUpdateError::Frozen)
    );
    let id_map = condition::boot_id_map();
    assert!(id_map.is_enabled(AlternativeId::TestEnabled));
    assert!(!id_map.is_enabled(AlternativeId::TestDisabled));
}

#[ktest]
fn boot_patching_is_claimed() {
    assert_eq!(
        alternatives::claim_boot_patch_attempt(&BOOT_PATCHING_ATTEMPTED),
        Err(AlternativesError::AlreadyAttempted)
    );
}

#[ktest]
fn repeated_patching_attempts_are_rejected() {
    let attempted = AtomicBool::new(false);
    assert_eq!(alternatives::claim_boot_patch_attempt(&attempted), Ok(()));
    assert_eq!(
        alternatives::claim_boot_patch_attempt(&attempted),
        Err(AlternativesError::AlreadyAttempted)
    );
}
