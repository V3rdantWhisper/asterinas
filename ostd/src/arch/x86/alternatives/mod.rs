// SPDX-License-Identifier: MPL-2.0

//! One-shot instruction replacement before starting application processors.
//!
//! The Rust and assembly macros size each slot to the longer instruction sequence
//! and emit replacement bytes and self-relative descriptors.
//! Policy owners select individual conditions before the BSP freezes the bitmap.
//! All records, including disabled ones, are validated before any write.
//! Each site must audit both instruction sequences and their execution paths.
//!
//! Replacements cannot require address relocation.
//! Live patching is unsupported:
//! disabling IRQs is insufficient if an NMI, exception, or another CPU can reach
//! a slot during a write.
//! Adding a site requires auditing those execution paths.

mod alternative_macros;
mod condition;
mod patch;
mod table;
#[cfg(ktest)]
mod test;

use core::sync::atomic::{AtomicBool, Ordering};

// The boot tests exercise the update interface until mitigation policies are added.
#[cfg_attr(not(ktest), expect(unused_imports))]
pub(super) use condition::{
    AlternativeId, AlternativeUpdateError, disable_condition, enable_condition,
};

const NOP_BYTE: u8 = 0x90;
static BOOT_PATCHING_ATTEMPTED: AtomicBool = AtomicBool::new(false);

/// Applies boot alternatives on the BSP, before starting any AP.
///
/// All descriptors are validated before the first write.
/// A failed attempt stops boot and cannot be retried; no rollback is performed.
/// All policy owners must finish updating their conditions before this call.
///
/// # Safety
///
/// The caller must be the BSP, after the writable kernel mapping and heap are available,
/// before starting any AP.
/// No asynchronous or fault path may execute a target slot during this call.
/// Every site's original instructions must be safe to execute before patching.
/// The selected instructions must uphold the surrounding code's contract
/// and be supported by every CPU that will execute the site.
/// No code may hold references into target slots while they are modified.
pub(super) unsafe fn apply_on_bsp() {
    claim_boot_patch_attempt(&BOOT_PATCHING_ATTEMPTED)
        .expect("boot alternatives have already been attempted");

    #[cfg(ktest)]
    {
        test::check_original_instructions();
        test::configure_conditions();
    }

    let id_map = condition::freeze_on_bsp();

    // SAFETY: No slot is modified during validation. The caller supplies the
    // active kernel mapping, and all APs are still offline.
    let patches = unsafe { table::validate_linked_alternatives(id_map) }
        .expect("failed to validate boot alternatives");
    // SAFETY: The whole table has passed validation. The caller upholds the
    // write and execution constraints, including NMI and fault paths. The test
    // variants use integer instructions and LFENCE, available on all x86-64 CPUs.
    let patched =
        unsafe { patch::commit_patches(&patches) }.expect("failed to apply boot alternatives");
    crate::debug!("alternatives: patched {} instruction slots", patched);
}

#[derive(Debug, PartialEq)]
enum AlternativesError {
    AlreadyAttempted,
    InvalidTable,
    InvalidLength,
    AddressOverflow,
    OutsideText,
    OutsideReplacement,
    UnknownCondition,
    OverlappingSlots,
    VerificationFailed,
}

fn claim_boot_patch_attempt(attempted: &AtomicBool) -> Result<(), AlternativesError> {
    attempted
        .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
        .map(|_| ())
        .map_err(|_| AlternativesError::AlreadyAttempted)
}
