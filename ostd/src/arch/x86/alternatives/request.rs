// SPDX-License-Identifier: MPL-2.0

//! Local patch builders and their internal prepared batches.
//!
//! Owners resolve their policies before submitting requests. Sites without a
//! request keep their current instructions. A batch describes one final conversion per site,
//! not a sequence of commands and not a globally atomic transaction.
//!
//! Both phases expose a consuming `commit` method. Batch preparation remains
//! internal; the phase selects the appropriate execution protocol.

#[cfg(ktest)]
mod test;

use alloc::vec::Vec;
use core::{
    marker::PhantomData,
    ops::Range,
    sync::atomic::{AtomicBool, Ordering},
};

use super::{
    AlternativesError,
    encoding::{self, AlternativeControlTransfer},
    patch,
    registry::{
        AlternativeBranch, AlternativeCall, AlternativeCallTrampoline, AlternativeGroup,
        AlternativeSequence, AlternativeTailCall, AlternativeTailCallTarget,
    },
    runtime,
    table::{AlternativeSelection, AlternativeSitePayload, AlternativeTable},
};

static BOOT_PATCHING_ATTEMPTED: AtomicBool = AtomicBool::new(false);

/// The phase permitting instruction replacement before AP startup.
pub(in crate::arch) enum AlternativeBoot {}
/// The phase permitting only supported control-transfer conversions.
pub(in crate::arch) enum AlternativeRuntime {}

pub(in crate::arch) trait AlternativePhase: sealed::Phase {}
impl sealed::Phase for AlternativeBoot {}
impl AlternativePhase for AlternativeBoot {}
impl sealed::Phase for AlternativeRuntime {}
impl AlternativePhase for AlternativeRuntime {}
mod sealed {
    pub(in crate::arch) trait Phase {}
}

/// The logical state of a branch whose enabled path is its fixed destination.
#[derive(Clone, Copy)]
pub(in crate::arch) enum AlternativeBranchState {
    #[cfg_attr(not(ktest), expect(dead_code))]
    Disabled,
    #[cfg_attr(not(ktest), expect(dead_code))]
    Enabled,
}

/// The state of a call slot that either falls through or invokes a trampoline.
#[derive(Clone, Copy)]
pub(in crate::arch) enum AlternativeCallState {
    #[cfg_attr(not(ktest), expect(dead_code))]
    Disabled,
    #[cfg_attr(not(ktest), expect(dead_code))]
    Enabled(AlternativeCallTrampoline),
}

/// A builder for typed patch requests against one immutable catalog.
pub(in crate::arch) struct AlternativePatchBuilder<'a, P: AlternativePhase> {
    table: &'a AlternativeTable,
    requests: Vec<AlternativePatchRequest>,
    phase: PhantomData<P>,
}

impl<'a, P: AlternativePhase> AlternativePatchBuilder<'a, P> {
    pub(in crate::arch) fn new(table: &'a AlternativeTable) -> Self {
        Self {
            table,
            requests: Vec::new(),
            phase: PhantomData,
        }
    }

    /// Requests a NOP/JMP conversion with an explicit expected state.
    #[cfg_attr(not(ktest), expect(dead_code))]
    pub(in crate::arch) fn set_branch<G: AlternativeGroup<Kind = AlternativeBranch>>(
        &mut self,
        selection: AlternativeSelection<'a, G>,
        expected: AlternativeBranchState,
        desired: AlternativeBranchState,
    ) -> Result<(), AlternativesError> {
        self.push(
            selection,
            AlternativePatchOperation::Branch { expected, desired },
        )
    }

    /// Retargets a tail-call slot without changing its group's calling convention.
    #[cfg_attr(not(ktest), expect(dead_code))]
    pub(in crate::arch) fn retarget_tail_call<G: AlternativeGroup<Kind = AlternativeTailCall>>(
        &mut self,
        selection: AlternativeSelection<'a, G>,
        expected: AlternativeTailCallTarget<G>,
        desired: AlternativeTailCallTarget<G>,
    ) -> Result<(), AlternativesError> {
        self.push(
            selection,
            AlternativePatchOperation::TailCall {
                expected: expected.address(),
                desired: desired.address(),
            },
        )
    }

    /// Requests a NOP/CALL conversion with an explicit expected state.
    #[cfg_attr(not(ktest), expect(dead_code))]
    pub(in crate::arch) fn set_call<G: AlternativeGroup<Kind = AlternativeCall>>(
        &mut self,
        selection: AlternativeSelection<'a, G>,
        expected: AlternativeCallState,
        desired: AlternativeCallState,
    ) -> Result<(), AlternativesError> {
        self.push(
            selection,
            AlternativePatchOperation::Call { expected, desired },
        )
    }
}

impl AlternativePatchBuilder<'_, AlternativeRuntime> {
    /// Consumes the builder and applies control-transfer requests on live CPUs.
    ///
    /// Commits are serialized. Every expected instruction is checked before any
    /// write; an error leaves all sites unchanged. During a successful commit,
    /// individual sites may execute either the old or the new behavior. Success
    /// does not mean that previously entered callbacks have finished executing.
    /// Returns an error before SMP initialization, without a current task, in an
    /// IRQ handler, or with local IRQs disabled.
    ///
    /// # Panics
    ///
    /// Panics if preemption is disabled, or if writing or CPU synchronization
    /// fails after patching starts. Such failures cannot be recovered by retrying.
    ///
    /// # Safety
    ///
    /// The caller must not invoke this method from an exception handler, even one
    /// that has enabled IRQs. This restriction is a caller obligation and is not
    /// detected by the runtime context checks.
    ///
    /// All target slots must remain writable in the validated kernel mapping.
    /// No other mechanism may write them or hold Rust references into them.
    /// Both behaviors must obey the site's contract in every execution context,
    /// including ordinary IRQs, and their code and dependencies must remain
    /// resident. Sites reachable from NMI or MCE handlers are not supported.
    /// No control flow may enter the middle of a slot. The patcher, breakpoint
    /// entry/exit, handler, and their dependencies must not contain selected sites
    /// or depend on the behaviors being changed. Callbacks must not recursively
    /// commit or wait for this commit. CPU membership must stay fixed, and
    /// supervisor CET must be disabled throughout the operation.
    #[cfg_attr(not(ktest), expect(dead_code))]
    pub(in crate::arch) unsafe fn commit(self) -> Result<usize, AlternativesError> {
        runtime::check_context()?;
        let batch = self.prepare()?;
        // SAFETY: The caller provides the live-code and context contracts above.
        unsafe { runtime::apply_batch(batch) }
    }
}

impl<'a> AlternativePatchBuilder<'a, AlternativeBoot> {
    /// Consumes the builder and applies its requests on the BSP before AP startup.
    ///
    /// All owners must finish submitting requests before this call. Control-site
    /// expectations are checked before any write. No rollback is provided, and a
    /// claimed boot patching attempt cannot be retried with a new builder.
    ///
    /// # Panics
    ///
    /// Panics if request preparation fails, boot patching was already attempted,
    /// or instruction validation or writing fails. Such failures stop boot.
    ///
    /// # Safety
    ///
    /// The caller must be the BSP, after the writable kernel mapping and heap
    /// are available and before any AP starts. No asynchronous or fault path may
    /// execute a target slot during this call, including NMI and MCE handlers.
    /// Every site's original instructions must be safe before patching, and the
    /// selected instructions must uphold the surrounding code's contract and be
    /// supported by every CPU that will execute the site. No code may hold
    /// references into target slots while they are modified.
    pub(in crate::arch) unsafe fn commit(self) {
        let batch = self.prepare().expect("failed to prepare boot alternatives");
        claim_boot_patch_attempt(&BOOT_PATCHING_ATTEMPTED)
            .expect("boot alternatives have already been attempted");
        // SAFETY: The caller upholds the boot execution and mapping contracts.
        // The image passed OSDK's ELF check; preparation checked request conflicts.
        let patched =
            unsafe { patch::apply_batch(batch) }.expect("failed to apply boot alternatives");
        crate::debug!("alternatives: patched {} instruction slots", patched);
    }

    /// Selects the linked replacement of a boot-only sequence group.
    #[cfg_attr(not(ktest), expect(dead_code))]
    pub(in crate::arch) fn replace_sequence<G: AlternativeGroup<Kind = AlternativeSequence>>(
        &mut self,
        selection: AlternativeSelection<'a, G>,
    ) -> Result<(), AlternativesError> {
        self.push(selection, AlternativePatchOperation::Sequence)
    }
}

impl<'a, P: AlternativePhase> AlternativePatchBuilder<'a, P> {
    /// Consumes all requests and prepares a conflict-free, address-sorted batch.
    ///
    /// This does not read or modify executable bytes. Expected bytes must be
    /// checked by the executor while it excludes other writers. Empty
    /// builders are valid, but empty selections are rejected on submission.
    fn prepare(self) -> Result<AlternativePatchBatch<P>, AlternativesError> {
        let mut patches = Vec::new();
        for request in &self.requests {
            for &index in &request.indices {
                patches.push(self.prepare_patch(index, &request.operation)?);
            }
        }
        patches.sort_unstable_by_key(|patch| patch.target.start);
        if patches
            .windows(2)
            .any(|pair| pair[0].target.end > pair[1].target.start)
        {
            return Err(AlternativesError::ConflictingRequests);
        }
        Ok(AlternativePatchBatch {
            patches,
            phase: PhantomData,
        })
    }

    fn push<G: AlternativeGroup>(
        &mut self,
        selection: AlternativeSelection<'a, G>,
        operation: AlternativePatchOperation,
    ) -> Result<(), AlternativesError> {
        let indices = selection.into_indices(self.table)?;
        self.requests
            .push(AlternativePatchRequest { indices, operation });
        Ok(())
    }

    fn prepare_patch(
        &self,
        index: usize,
        operation: &AlternativePatchOperation,
    ) -> Result<AlternativePatch, AlternativesError> {
        let site = self.table.site(index);
        let address = site.target.start;
        let data = match (operation, &site.payload) {
            (
                AlternativePatchOperation::Sequence,
                AlternativeSitePayload::Sequence(replacement),
            ) => AlternativePatchData::Sequence(replacement.clone()),
            (
                AlternativePatchOperation::Branch { expected, desired },
                AlternativeSitePayload::Branch(destination),
            ) => {
                let encode_fn = |state| match state {
                    AlternativeBranchState::Disabled => Ok(encoding::CONTROL_NOP),
                    AlternativeBranchState::Enabled => encoding::encode_control_transfer(
                        AlternativeControlTransfer::Jump,
                        address,
                        *destination,
                    ),
                };
                AlternativePatchData::Control {
                    expected: encode_fn(*expected)?,
                    replacement: encode_fn(*desired)?,
                }
            }
            (
                AlternativePatchOperation::TailCall { expected, desired },
                AlternativeSitePayload::TailCall,
            ) => {
                self.check_destination(*expected, &site.target)?;
                self.check_destination(*desired, &site.target)?;
                AlternativePatchData::Control {
                    expected: encoding::encode_control_transfer(
                        AlternativeControlTransfer::Jump,
                        address,
                        *expected,
                    )?,
                    replacement: encoding::encode_control_transfer(
                        AlternativeControlTransfer::Jump,
                        address,
                        *desired,
                    )?,
                }
            }
            (
                AlternativePatchOperation::Call { expected, desired },
                AlternativeSitePayload::Call,
            ) => {
                let encode_fn = |state| match state {
                    AlternativeCallState::Disabled => Ok(encoding::CONTROL_NOP),
                    AlternativeCallState::Enabled(trampoline) => {
                        self.check_destination(trampoline.address(), &site.target)?;
                        encoding::encode_control_transfer(
                            AlternativeControlTransfer::Call,
                            address,
                            trampoline.address(),
                        )
                    }
                };
                AlternativePatchData::Control {
                    expected: encode_fn(*expected)?,
                    replacement: encode_fn(*desired)?,
                }
            }
            _ => return Err(AlternativesError::InvalidKind),
        };
        Ok(AlternativePatch {
            target: site.target.clone(),
            data,
        })
    }

    fn check_destination(
        &self,
        destination: usize,
        target: &Range<usize>,
    ) -> Result<(), AlternativesError> {
        if !self.table.contains_text_address(destination) {
            return Err(AlternativesError::OutsideText);
        }
        if target.contains(&destination) {
            return Err(AlternativesError::OverlappingSlots);
        }
        Ok(())
    }
}

/// An owned set of prepared writes; only the matching executor may consume it.
///
/// Consuming this object prevents reuse of this batch, not creation of another
/// batch. The boot executor separately enforces its one-attempt contract.
#[must_use]
pub(super) struct AlternativePatchBatch<P: AlternativePhase> {
    patches: Vec<AlternativePatch>,
    phase: PhantomData<P>,
}

impl<P: AlternativePhase> AlternativePatchBatch<P> {
    pub(super) fn patches(&self) -> &[AlternativePatch] {
        &self.patches
    }
}

struct AlternativePatchRequest {
    indices: Vec<usize>,
    operation: AlternativePatchOperation,
}

enum AlternativePatchOperation {
    Sequence,
    Branch {
        expected: AlternativeBranchState,
        desired: AlternativeBranchState,
    },
    TailCall {
        expected: usize,
        desired: usize,
    },
    Call {
        expected: AlternativeCallState,
        desired: AlternativeCallState,
    },
}

pub(super) struct AlternativePatch {
    target: Range<usize>,
    data: AlternativePatchData,
}

impl AlternativePatch {
    pub(super) fn target(&self) -> &Range<usize> {
        &self.target
    }

    pub(super) fn data(&self) -> &AlternativePatchData {
        &self.data
    }
}

pub(super) enum AlternativePatchData {
    // Boot sequences rely on the original-code boot contract. A snapshot of
    // current bytes would not prove that they are the original instructions.
    Sequence(Range<usize>),
    Control {
        expected: [u8; encoding::CONTROL_SLOT_LEN],
        replacement: [u8; encoding::CONTROL_SLOT_LEN],
    },
}

fn claim_boot_patch_attempt(attempted: &AtomicBool) -> Result<(), AlternativesError> {
    attempted
        .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
        .map(|_| ())
        .map_err(|_| AlternativesError::AlreadyAttempted)
}
