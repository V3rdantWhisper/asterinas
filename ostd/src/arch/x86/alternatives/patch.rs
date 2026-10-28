// SPDX-License-Identifier: MPL-2.0

//! Boot-time writes, expected-byte checks, and local instruction serialization.
//!
//! Runtime writes use the separate SMP protocol in `runtime`.

use core::sync::atomic::{self, Ordering};

use super::{
    AlternativesError,
    request::{AlternativeBoot, AlternativePatch, AlternativePatchBatch, AlternativePatchData},
};

/// Consumes a boot batch, checks every expected instruction, and commits its writes.
///
/// A failed expected-byte check makes no changes. A failure after writing starts
/// is fatal to boot; no rollback is promised. Sequence originals are established
/// by the boot caller's contract, not inferred from a snapshot of current text.
///
/// # Safety
///
/// The caller must uphold the execution, CPU, and mapping contracts of
/// boot builder's `commit` method.
/// Every target must be writable, exclusively owned, and unreachable throughout
/// this operation, including from NMI and fault handlers. Linked replacement
/// bytes must remain readable and immutable, with no references into targets.
/// The batch's table must come from an image satisfying `from_linked_image`'s
/// final ELF validation and loading contract.
pub(super) unsafe fn apply_batch(
    batch: AlternativePatchBatch<AlternativeBoot>,
) -> Result<usize, AlternativesError> {
    // TODO: Allow NMI-reachable boot sites through a fixed NMI entry stub. The
    // vector-2 stub must check a RIP-relative pause flag before entering common
    // trap code or touching GS, and return through an unpatched path while
    // normal NMI dispatch is paused. The stub, flag access, return path, and all
    // their dependencies must exclude every patch site, including sequences.
    // Publish the pause before writing and clear it only after instruction
    // serialization, with compiler/CPU ordering enforced. NMI must never wait
    // for this writer: it may have interrupted the writer on the same CPU.
    // This scheme requires a valid entry stack and a boot policy that permits
    // suppressing normal dispatch while retaining any required source handling;
    // an early return alone does not preserve an event for later delivery.
    // It applies only to ordinary BSP boot code before APs or userspace run.
    // Runtime use also requires draining handlers already past the check and
    // handling entry/stack transitions. Linux's stop_nmi()/ignore_nmis in
    // arch/x86/kernel/{alternative,nmi}.c suppress normal dispatch, but do not
    // prevent execution of the entry/exit code surrounding that check.
    // No such exclusion is implemented yet; callers must keep NMI-reachable
    // sites out of this batch. This plan does not provide MCE exclusion.
    let _irq_guard = crate::irq::disable_local();
    // SAFETY: All sites are mapped and exclusively owned under the caller's
    // boot contract. No writer can invalidate a checked instruction before use.
    unsafe { validate_expected_bytes(batch.patches())? };

    for patch in batch.patches() {
        let target = patch.target();
        // SAFETY: Linked replacements remain readable; control encodings are
        // owned by the batch. The final ELF check establishes disjoint ranges.
        let replacement = unsafe { replacement_bytes(patch.data()) };
        // SAFETY: The final ELF check establishes lengths and target ranges;
        // the builder encodes control replacements to exactly fit their slots.
        // The caller excludes all execution and references to these targets.
        unsafe {
            core::ptr::copy_nonoverlapping(
                replacement.as_ptr(),
                target.start as *mut u8,
                replacement.len(),
            );
            core::ptr::write_bytes(
                (target.start + replacement.len()) as *mut u8,
                super::NOP_BYTE,
                target.len() - replacement.len(),
            );
        }
    }

    for patch in batch.patches() {
        let target = patch.target();
        // SAFETY: The same immutable sources remain valid during verification.
        let replacement = unsafe { replacement_bytes(patch.data()) };
        for offset in 0..target.len() {
            let expected = replacement.get(offset).copied().unwrap_or(super::NOP_BYTE);
            // SAFETY: The offset lies within the mapped, exclusively owned slot.
            let actual = unsafe { ((target.start + offset) as *const u8).read_volatile() };
            if actual != expected {
                return Err(AlternativesError::VerificationFailed);
            }
        }
    }

    // Intel SDM Vol. 3A, "Self-Modifying Code": execute a serializing instruction
    // between writing code and executing it. APs have not started yet.
    atomic::compiler_fence(Ordering::SeqCst);
    core::arch::x86_64::__cpuid(0);
    atomic::compiler_fence(Ordering::SeqCst);
    Ok(batch.patches().len())
}

/// Checks all control-transfer expectations before the first write.
///
/// # Safety
///
/// Every patch's target must be mapped and readable. No writer may modify these
/// locations concurrently. Sequence sources are not accessed by this check.
pub(super) unsafe fn validate_expected_bytes(
    patches: &[AlternativePatch],
) -> Result<(), AlternativesError> {
    for patch in patches {
        let target = patch.target();
        let AlternativePatchData::Control { expected, .. } = patch.data() else {
            continue;
        };
        for (offset, &byte) in expected.iter().enumerate() {
            // SAFETY: The caller guarantees readable, stable target storage.
            let actual = unsafe { ((target.start + offset) as *const u8).read_volatile() };
            if actual != byte {
                return Err(AlternativesError::UnexpectedInstruction);
            }
        }
    }
    Ok(())
}

/// Borrows immutable replacement bytes for the duration of the write.
///
/// # Safety
///
/// A sequence range must refer to permanently resident, immutable replacement
/// storage in the linked kernel image and must be valid for a shared slice.
unsafe fn replacement_bytes(data: &AlternativePatchData) -> &[u8] {
    match data {
        AlternativePatchData::Sequence(range) => {
            // SAFETY: The caller guarantees the linked replacement's lifetime,
            // readability, and immutability, even for a zero-length sequence.
            unsafe { core::slice::from_raw_parts(range.start as *const u8, range.len()) }
        }
        AlternativePatchData::Control { replacement, .. } => replacement,
    }
}
