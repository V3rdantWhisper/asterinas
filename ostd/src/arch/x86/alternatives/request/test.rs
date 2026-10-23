// SPDX-License-Identifier: MPL-2.0

use super::*;
use crate::{arch::alternatives::registry::groups, prelude::*};

fn linked_table() -> AlternativeTable {
    // SAFETY: OSDK checked this ELF; loading preserves its layout and immutable
    // metadata. Boot patching only modifies instruction bytes within target slots.
    unsafe { AlternativeTable::from_linked_image().unwrap() }
}

#[ktest]
fn overlapping_requests_are_rejected() {
    let table = linked_table();
    let mut builder = AlternativePatchBuilder::<AlternativeBoot>::new(&table);
    builder
        .replace_sequence(table.all::<groups::TestSequence>())
        .unwrap();
    builder
        .replace_sequence(
            table
                .select(table.sites::<groups::TestSequence>().take(1))
                .unwrap(),
        )
        .unwrap();
    assert_eq!(
        builder.prepare().err(),
        Some(AlternativesError::ConflictingRequests)
    );
}

#[ktest]
fn selections_cannot_cross_catalogs_or_be_empty() {
    let first = linked_table();
    let second = linked_table();
    assert_eq!(
        first.select(second.sites::<groups::TestSequence>()).err(),
        Some(AlternativesError::ForeignTable)
    );
    let mut builder = AlternativePatchBuilder::<AlternativeBoot>::new(&first);
    assert_eq!(
        builder.replace_sequence(second.all::<groups::TestSequence>()),
        Err(AlternativesError::ForeignTable)
    );
    let empty = first
        .select(first.sites::<groups::TestSequence>().take(0))
        .unwrap();
    assert_eq!(
        builder.replace_sequence(empty),
        Err(AlternativesError::EmptySelection)
    );
    assert!(builder.prepare().unwrap().patches.is_empty());
}

#[ktest]
fn runtime_requests_prepare_reverse_branches_without_writing() {
    let table = linked_table();
    let mut builder = AlternativePatchBuilder::<AlternativeRuntime>::new(&table);
    builder
        .set_branch(
            table.all::<groups::TestBranch>(),
            AlternativeBranchState::Enabled,
            AlternativeBranchState::Disabled,
        )
        .unwrap();
    let batch = builder.prepare().unwrap();
    assert_eq!(batch.patches.len(), 2);
    for patch in batch.patches {
        let AlternativePatchData::Control {
            expected,
            replacement,
        } = patch.data
        else {
            panic!("not a branch")
        };
        assert_eq!(expected[0], 0xe9);
        assert_eq!(replacement, encoding::CONTROL_NOP);
    }
}

#[ktest]
fn stale_expectations_fail_before_writing() {
    let table = linked_table();
    let mut builder = AlternativePatchBuilder::<AlternativeRuntime>::new(&table);
    // One of these two sites was enabled at boot, so they cannot both be NOPs.
    builder
        .set_branch(
            table.all::<groups::TestBranch>(),
            AlternativeBranchState::Disabled,
            AlternativeBranchState::Enabled,
        )
        .unwrap();
    let batch = builder.prepare().unwrap();
    // SAFETY: Boot patching is over; these linked sites remain mapped and no
    // runtime writer exists. This check itself performs no writes.
    assert_eq!(
        unsafe { patch::validate_expected_bytes(&batch.patches) },
        Err(AlternativesError::UnexpectedInstruction)
    );
}

#[ktest]
fn relative_control_transfers_check_both_displacement_limits() {
    use encoding::AlternativeControlTransfer::Jump;
    let address = 0x1_0000_0000usize;
    let next = address + encoding::CONTROL_SLOT_LEN;
    for displacement in [i32::MIN, -1, 0, i32::MAX] {
        let destination = next.checked_add_signed(displacement as isize).unwrap();
        let bytes = encoding::encode_control_transfer(Jump, address, destination).unwrap();
        assert_eq!(
            i32::from_le_bytes(bytes[1..].try_into().unwrap()),
            displacement
        );
    }
    assert_eq!(
        encoding::encode_control_transfer(Jump, address, next + i32::MAX as usize + 1),
        Err(AlternativesError::DisplacementOutOfRange)
    );
    assert_eq!(
        encoding::encode_control_transfer(Jump, address, next - (i32::MAX as usize + 2)),
        Err(AlternativesError::DisplacementOutOfRange)
    );
    assert_eq!(
        encoding::encode_control_transfer(Jump, usize::MAX, 0),
        Err(AlternativesError::AddressOverflow)
    );
}

#[ktest]
fn boot_patching_is_claimed() {
    assert_eq!(
        claim_boot_patch_attempt(&BOOT_PATCHING_ATTEMPTED),
        Err(AlternativesError::AlreadyAttempted)
    );
}

#[ktest]
fn repeated_patching_attempts_are_rejected() {
    let attempted = AtomicBool::new(false);
    assert_eq!(claim_boot_patch_attempt(&attempted), Ok(()));
    assert_eq!(
        claim_boot_patch_attempt(&attempted),
        Err(AlternativesError::AlreadyAttempted)
    );
}
