// SPDX-License-Identifier: MPL-2.0

//! Boot-time execution coverage for all supported site contracts.
//!
//! Configuration checks original code before preparing the single boot batch.
//! Kernel tests later exercise the resulting code without modifying live text.

use core::{
    arch::{asm, global_asm},
    sync::atomic::{AtomicU64, Ordering},
};

use super::{
    alternative_macros::{alternative, alternative_asm_template},
    registry::{AlternativeCallTrampoline, AlternativeId, groups},
    request::{
        AlternativeBoot, AlternativeBranchState, AlternativeCallState, AlternativePatchBuilder,
    },
    table::AlternativeTable,
};
use crate::prelude::*;

#[unsafe(no_mangle)]
static ostd_alt_test_trace_count: AtomicU64 = AtomicU64::new(0);

global_asm!(
    include_str!("alternative_macros.S"),
    include_str!("test.S"),
    ".purgem OSTD_ALTERNATIVE",
    ".purgem OSTD_ALTERNATIVE_BRANCH",
    ".purgem OSTD_ALTERNATIVE_TAIL_CALL",
    ".purgem OSTD_ALTERNATIVE_CALL",
    ".purgem OSTD_ALTERNATIVE_DESCRIPTOR",
    replace_add_group_id = const AlternativeId::TestSequence.as_raw(),
    branch_group_id = const AlternativeId::TestBranch.as_raw(),
    tail_call_group_id = const AlternativeId::TestTailCall.as_raw(),
    trace_group_id = const AlternativeId::TestTrace.as_raw(),
);

unsafe extern "C" {
    fn ostd_alt_test_branch() -> u64;
    fn ostd_alt_test_branch_unselected() -> u64;
    fn ostd_alt_test_tail_call(value: u64) -> u64;
    fn ostd_alt_test_old_handler(value: u64) -> u64;
    fn ostd_alt_test_new_handler(value: u64) -> u64;
    fn ostd_alt_test_traced(value: u64) -> u64;
    fn ostd_alt_test_trace_trampoline();
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
            alt_group_id = const AlternativeId::TestSequence.as_raw(),
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
            alt_group_id = const AlternativeId::TestDisabled.as_raw(),
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
            alt_group_id = const AlternativeId::TestEnabled.as_raw(),
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
            alt_group_id = const AlternativeId::TestSequence.as_raw(),
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
        alternative!("", "lfence", groups::TestSequence);
    }
}

#[inline(never)]
fn alt_test_rust_remove_lfence() {
    // SAFETY: This fence is only a test site, not a required synchronization
    // point. Both variants preserve registers, flags, and the stack.
    unsafe {
        alternative!("lfence", "", groups::TestSequence);
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

pub(in crate::arch) fn configure_test_alternatives<'a>(
    table: &'a AlternativeTable,
    builder: &mut AlternativePatchBuilder<'a, AlternativeBoot>,
) {
    check_original_instructions();
    // SAFETY: These test leaves obey their declared SysV signatures and cannot
    // execute concurrently with boot patching or any exception handler.
    unsafe {
        assert_eq!(ostd_alt_test_branch(), 1);
        assert_eq!(ostd_alt_test_branch_unselected(), 1);
        assert_eq!(ostd_alt_test_tail_call(10), 11);
        assert_eq!(ostd_alt_test_traced(10), 11);
    }
    assert_eq!(ostd_alt_test_trace_count.load(Ordering::Relaxed), 0);

    builder
        .replace_sequence(table.all::<groups::TestSequence>())
        .unwrap();
    builder
        .replace_sequence(table.all::<groups::TestEnabled>())
        .unwrap();
    // TestDisabled receives no request. Selecting one member of TestBranch
    // exercises a per-site filter within a shared group, as tracing/logging need.
    let selected = table
        .select(
            table
                .sites::<groups::TestBranch>()
                .filter(|site| site.address() == ostd_alt_test_branch as *const () as usize),
        )
        .unwrap();
    builder
        .set_branch(
            selected,
            AlternativeBranchState::Disabled,
            AlternativeBranchState::Enabled,
        )
        .unwrap();
    builder
        .retarget_tail_call(
            table.all::<groups::TestTailCall>(),
            groups::TestTailCall::target(ostd_alt_test_old_handler),
            groups::TestTailCall::target(ostd_alt_test_new_handler),
        )
        .unwrap();
    // SAFETY: The assembly trampoline preserves all GPRs and flags, restores
    // the stack, and only increments a permanently resident atomic counter.
    let trampoline = unsafe {
        AlternativeCallTrampoline::new(ostd_alt_test_trace_trampoline as *const () as usize)
    };
    builder
        .set_call(
            table.all::<groups::TestTrace>(),
            AlternativeCallState::Disabled,
            AlternativeCallState::Enabled(trampoline),
        )
        .unwrap();
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
fn branch_tail_call_and_call_sites_execute() {
    let trace_count = ostd_alt_test_trace_count.load(Ordering::Relaxed);
    // SAFETY: Boot patching is complete and each leaf retains its declared ABI.
    unsafe {
        assert_eq!(ostd_alt_test_branch(), 42);
        assert_eq!(ostd_alt_test_branch_unselected(), 1);
        assert_eq!(ostd_alt_test_tail_call(10), 52);
        assert_eq!(ostd_alt_test_traced(10), 11);
    }
    assert_eq!(
        ostd_alt_test_trace_count.load(Ordering::Relaxed),
        trace_count + 1
    );
}

#[ktest]
fn raw_group_ids_are_checked() {
    for (index, &id) in AlternativeId::ALL.iter().enumerate() {
        assert_eq!(id.as_raw() as usize, index);
        assert_eq!(AlternativeId::from_raw(id.as_raw()), Some(id));
    }
    assert_eq!(
        AlternativeId::from_raw(AlternativeId::ALL.len() as u32),
        None
    );
    assert_eq!(AlternativeId::from_raw(u32::MAX), None);
}
