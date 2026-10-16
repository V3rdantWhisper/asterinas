// SPDX-License-Identifier: MPL-2.0

//! Instruction writes, readback verification, and local CPU serialization.

use core::sync::atomic::{self, Ordering};

use super::{AlternativesError, table::AlternativePatch};

/// Writes enabled patches and serializes instruction execution before returning.
///
/// # Safety
///
/// Every patch must have passed descriptor validation against the live kernel
/// image's disjoint text and replacement sections.
/// The caller must uphold [`super::apply_on_bsp`]'s boot and execution
/// requirements and exclusively own the writable target slots.
/// No references into those slots may exist during this call.
/// Source bytes must remain readable and immutable.
/// An error is fatal to boot; there is no rollback.
pub(super) unsafe fn commit_patches(
    patches: &[AlternativePatch],
) -> Result<usize, AlternativesError> {
    // Calibration can enable IRQs earlier in boot. Protect the actual commit
    // rather than assuming IF has remained clear since the BSP entry point.
    let _irq_guard = crate::irq::disable_local();
    let mut patched = 0;
    for patch in patches.iter().filter(|patch| patch.is_enabled()) {
        let target_range = patch.target_range();
        let replacement_range = patch.replacement_range();

        // SAFETY: Validation checked lengths and bounds in disjoint sections.
        // The caller guarantees writable, exclusively accessed
        // slots that cannot execute during the commit.
        unsafe {
            core::ptr::copy_nonoverlapping(
                replacement_range.start as *const u8,
                target_range.start as *mut u8,
                replacement_range.len(),
            );
            core::ptr::write_bytes(
                (target_range.start + replacement_range.len()) as *mut u8,
                super::NOP_BYTE,
                target_range.len() - replacement_range.len(),
            );
        }
        patched += 1;
    }

    for patch in patches.iter().filter(|patch| patch.is_enabled()) {
        let target_range = patch.target_range();
        let replacement_range = patch.replacement_range();

        for offset in 0..target_range.len() {
            let expected = if offset < replacement_range.len() {
                // SAFETY: The offset stays in the validated replacement range.
                unsafe { ((replacement_range.start + offset) as *const u8).read_volatile() }
            } else {
                super::NOP_BYTE
            };
            // SAFETY: The offset is inside the validated original slot.
            // A volatile read verifies memory rather than an optimized copy.
            let actual = unsafe { ((target_range.start + offset) as *const u8).read_volatile() };
            if actual != expected {
                return Err(AlternativesError::VerificationFailed);
            }
        }
    }

    // Intel SDM Vol. 3A, "Self-Modifying Code": execute a serializing instruction
    // between writing code and executing it. APs have not started yet. The
    // compiler fences also prevent compiler motion across this boundary.
    atomic::compiler_fence(Ordering::SeqCst);
    core::arch::x86_64::__cpuid(0);
    atomic::compiler_fence(Ordering::SeqCst);
    Ok(patched)
}
