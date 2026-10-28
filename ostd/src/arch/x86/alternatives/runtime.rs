// SPDX-License-Identifier: MPL-2.0

//! Serialized runtime commits using temporary breakpoints.
//!
//! The three-stage protocol follows Linux's `smp_text_poke_batch_finish` in
//! `arch/x86/kernel/alternative.c`: install INT3, synchronize all CPUs, write
//! tails, synchronize, restore heads, synchronize. Each slot is one instruction,
//! so an interrupted CPU can never resume inside the bytes being replaced.
//! See also Intel SDM Vol. 3A, "Handling Self- and Cross-Modifying Code".
//!
//! Lock order is writer mutex -> IPI queues. The breakpoint handler takes no
//! locks, allocates nothing, and never enables IRQs. Its reader count covers
//! nested exceptions as well as unrelated breakpoints racing with retirement.

#[cfg(ktest)]
mod test;

use alloc::{boxed::Box, vec::Vec};
use core::{
    ptr,
    sync::atomic::{self, AtomicPtr, AtomicUsize, Ordering},
};

use super::{
    AlternativesError,
    encoding::{self, AlternativeControlTransfer},
    patch,
    request::{AlternativePatchBatch, AlternativePatchData, AlternativeRuntime},
};
use crate::{arch::trap::TrapFrame, cpu::CpuSet, irq::InterruptLevel, smp, sync::Mutex, task};

const INT3: u8 = 0xcc;

static PATCH_WRITER: Mutex<()> = Mutex::new(());
static ACTIVE_PATCHES: AtomicPtr<RuntimePatches> = AtomicPtr::new(ptr::null_mut());
static BREAKPOINT_READERS: AtomicUsize = AtomicUsize::new(0);

pub(super) fn check_context() -> Result<(), AlternativesError> {
    if crate::IN_BOOTSTRAP_CONTEXT.load(Ordering::Relaxed) || smp::IPI_SENDER.get().is_none() {
        return Err(AlternativesError::RuntimeUnavailable);
    }
    if !crate::arch::irq::is_local_enabled()
        || !InterruptLevel::current().is_task_context()
        || task::Task::current().is_none()
    {
        return Err(AlternativesError::InvalidContext);
    }
    task::atomic_mode::might_sleep();
    Ok(())
}

/// Applies a prepared runtime batch, returning errors only before writing.
///
/// # Safety
///
/// The caller must uphold the runtime builder's `commit` contract and must have
/// called `check_context` in the current task before invoking this function.
// SAFETY: This section is executable text excluded from runtime alternatives.
#[inline(never)]
#[unsafe(link_section = ".text.alternatives_protected")]
pub(super) unsafe fn apply_batch(
    batch: AlternativePatchBatch<AlternativeRuntime>,
) -> Result<usize, AlternativesError> {
    // Allocate everything owned by the publication before modifying any code.
    let prepared = RuntimePatches::new(&batch)?;
    let cpus = CpuSet::new_full();
    let _writer = PATCH_WRITER.lock();
    if !ACTIVE_PATCHES.load(Ordering::SeqCst).is_null() {
        return Err(AlternativesError::PatchingPoisoned);
    }
    // SAFETY: The caller guarantees mapped sites and excludes external writers;
    // the mutex excludes every other runtime commit until verification completes.
    unsafe { patch::validate_expected_bytes(batch.patches())? };
    let count = prepared.sites.len();
    if count == 0 {
        return Ok(0);
    }

    // Ownership deliberately passes to the publication, not an unwinding guard.
    // If writing panics, INT3 may remain installed: retain its emulation metadata
    // permanently and reject later commits, including when ktest catches a panic.
    let published = Box::into_raw(prepared);
    ACTIVE_PATCHES.store(published, Ordering::SeqCst);
    atomic::fence(Ordering::SeqCst);
    // SAFETY: This allocation remains immutable and alive until retirement below.
    let patches = unsafe { &*published };
    let sites = &patches.sites;

    for site in sites {
        // SAFETY: A single-byte store is atomic on x86. The published handler
        // emulates the desired instruction before any tail byte can change.
        unsafe { write_byte(site.address, INT3) };
    }
    synchronize_cpus(&cpus);

    for site in sites {
        for offset in 1..encoding::CONTROL_SLOT_LEN {
            // SAFETY: Every CPU has serialized past installation of INT3. No
            // execution enters the tail, including ordinary IRQ execution of
            // the slot. NMI and MCE paths are not supported runtime site owners.
            unsafe { write_byte(site.address + offset, site.replacement[offset]) };
        }
    }
    synchronize_cpus(&cpus);

    for site in sites {
        // SAFETY: Every CPU has serialized after tail writes. Restoring the
        // first byte exposes only the complete desired instruction.
        unsafe { write_byte(site.address, site.replacement[0]) };
    }
    synchronize_cpus(&cpus);

    // No CPU can newly execute an old INT3 after the last synchronization.
    // Stop new readers before waiting for even unrelated handlers to release
    // their references. SeqCst orders this store against reader admission/load:
    // a reader either sees null or keeps the allocation alive through the wait.
    ACTIVE_PATCHES.store(ptr::null_mut(), Ordering::SeqCst);
    while BREAKPOINT_READERS.load(Ordering::SeqCst) != 0 {
        core::hint::spin_loop();
    }
    // SAFETY: Publication owns this Box; all readers have released it and new
    // readers cannot acquire it. The mutex prevents publication of another batch.
    drop(unsafe { Box::from_raw(published) });
    Ok(count)
}

/// Handles a kernel breakpoint belonging to the active runtime batch.
///
/// Returns false for unrelated breakpoints without changing their trap frames.
///
/// # Safety
///
/// `frame` must be a kernel INT3 frame created by `trap.S`, with its stack gap
/// intact and local IRQs disabled. Its saved RSP must refer to the interrupted
/// stack, which must have space for the return address of an emulated CALL.
// SAFETY: This section is executable text excluded from runtime alternatives.
#[inline(never)]
#[unsafe(link_section = ".text.alternatives_protected")]
pub(in crate::arch) unsafe fn handle_breakpoint(frame: &mut TrapFrame) -> bool {
    let _reader = BreakpointReader::new();
    let published = ACTIVE_PATCHES.load(Ordering::SeqCst);
    if published.is_null() {
        return false;
    }
    // SAFETY: Reader admission precedes the pointer load. Retirement cannot
    // free a non-null publication while this reader is alive.
    let patches = unsafe { &*published };
    let Some(address) = frame.rip.checked_sub(1) else {
        return false;
    };
    let Ok(index) = patches
        .sites
        .binary_search_by_key(&address, |site| site.address)
    else {
        return false;
    };
    let Some(site) = patches.sites.get(index) else {
        return false;
    };
    let Some(next) = address.checked_add(encoding::CONTROL_SLOT_LEN) else {
        return false;
    };
    match site.instruction {
        RuntimeInstruction::Nop => frame.rip = next,
        RuntimeInstruction::Jump(destination) => frame.rip = destination,
        RuntimeInstruction::Call(destination) => {
            let Some(stack_pointer) = frame.rsp.checked_sub(size_of::<usize>()) else {
                return false;
            };
            // SAFETY: trap.S reserves a gap above the frame. This is precisely
            // the stack word the replaced CALL would push, outside the borrowed
            // TrapFrame, and the site's contract permits writing that word.
            unsafe { (stack_pointer as *mut usize).write_unaligned(next) };
            frame.rsp = stack_pointer;
            frame.rip = destination;
        }
    }
    #[cfg(ktest)]
    test::record_breakpoint();
    true
}

// SAFETY: This section is executable text excluded from runtime alternatives.
#[inline(never)]
#[unsafe(link_section = ".text.alternatives_protected")]
fn synchronize_cpus(cpus: &CpuSet) {
    smp::inter_processor_call(cpus, serialize_instructions).wait();
    #[cfg(ktest)]
    test::yield_during_commit();
}

// SAFETY: This section is executable text excluded from runtime alternatives.
#[inline(never)]
#[unsafe(link_section = ".text.alternatives_protected")]
fn serialize_instructions() {
    atomic::compiler_fence(Ordering::SeqCst);
    core::arch::x86_64::__cpuid(0);
    atomic::compiler_fence(Ordering::SeqCst);
    #[cfg(ktest)]
    test::exercise_instructions();
}

/// Writes and reads back one byte without widening an instruction-head store.
///
/// # Safety
///
/// The address must be writable and belong to the active batch. Its execution
/// must be protected by the current stage of the INT3 protocol.
// SAFETY: This section is executable text excluded from runtime alternatives.
#[inline(never)]
#[unsafe(link_section = ".text.alternatives_protected")]
unsafe fn write_byte(address: usize, byte: u8) {
    // SAFETY: The caller provides the writable mapping and execution protocol.
    unsafe { (address as *mut u8).write_volatile(byte) };
    // SAFETY: The same mapping remains readable, with competing writers excluded.
    let actual = unsafe { (address as *const u8).read_volatile() };
    assert_eq!(
        actual, byte,
        "runtime alternative write verification failed"
    );
}

/// Immutable, temporary handler data, owned by `ACTIVE_PATCHES` while published.
struct RuntimePatches {
    sites: Vec<RuntimePatch>,
}

impl RuntimePatches {
    fn new(
        batch: &AlternativePatchBatch<AlternativeRuntime>,
    ) -> Result<Box<Self>, AlternativesError> {
        let mut sites = Vec::with_capacity(batch.patches().len());
        for patch in batch.patches() {
            let AlternativePatchData::Control { replacement, .. } = patch.data() else {
                return Err(AlternativesError::InvalidKind);
            };
            let address = patch.target().start;
            let instruction = if replacement == &encoding::CONTROL_NOP {
                RuntimeInstruction::Nop
            } else {
                let (transfer, destination) =
                    encoding::decode_control_transfer(address, replacement)?;
                match transfer {
                    AlternativeControlTransfer::Jump => RuntimeInstruction::Jump(destination),
                    AlternativeControlTransfer::Call => RuntimeInstruction::Call(destination),
                }
            };
            sites.push(RuntimePatch {
                address,
                replacement: *replacement,
                instruction,
            });
        }
        Ok(Box::new(Self { sites }))
    }
}

struct RuntimePatch {
    address: usize,
    replacement: [u8; encoding::CONTROL_SLOT_LEN],
    instruction: RuntimeInstruction,
}

enum RuntimeInstruction {
    Nop,
    Jump(usize),
    Call(usize),
}

/// A guard that pins a publication without locking, including from nested exceptions.
struct BreakpointReader;

impl BreakpointReader {
    #[inline(always)]
    fn new() -> Self {
        BREAKPOINT_READERS.fetch_add(1, Ordering::SeqCst);
        Self
    }
}

impl Drop for BreakpointReader {
    #[inline(always)]
    fn drop(&mut self) {
        BREAKPOINT_READERS.fetch_sub(1, Ordering::SeqCst);
    }
}
