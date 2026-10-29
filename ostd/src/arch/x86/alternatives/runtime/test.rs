// SPDX-License-Identifier: MPL-2.0

use core::{arch::global_asm, sync::atomic::AtomicU64};

use super::*;
use crate::{
    arch::alternatives::{
        AlternativeTable,
        registry::{AlternativeCallTrampoline, AlternativeId, groups},
        request::{AlternativeBranchState, AlternativeCallState, AlternativePatchBuilder},
    },
    prelude::*,
    sync::WaitQueue,
};

mod rust_sites;

// The hook runs on every CPU with IRQs disabled, inside all three serialization
// rounds. This deterministically exercises actual INT3 entry/return, rather than
// relying on a stress loop to happen to catch the short transitional window.
const EXERCISE_INACTIVE: usize = 0;
const EXERCISE_ORIGINAL: usize = 1;
const EXERCISE_REPLACEMENT: usize = 2;

static EXERCISE_STATE: AtomicUsize = AtomicUsize::new(EXERCISE_INACTIVE);
static EXERCISE_COUNT: AtomicUsize = AtomicUsize::new(0);
static BREAKPOINT_COUNT: AtomicUsize = AtomicUsize::new(0);
static TEST_LOCK: Mutex<()> = Mutex::new(());
static YIELD_DURING_COMMIT: atomic::AtomicBool = atomic::AtomicBool::new(false);

// The default ktest FIFO scheduler does not preempt tasks on timer ticks. Yield
// inside the commit, with the writer mutex still held, to force real overlap
// between pending commits and execution of sites in each transitional state.
pub(super) fn yield_during_commit() {
    if YIELD_DURING_COMMIT.load(Ordering::Relaxed) {
        task::Task::yield_now();
    }
}

struct CommitYieldGuard;

impl CommitYieldGuard {
    fn new() -> Self {
        YIELD_DURING_COMMIT.store(true, Ordering::Relaxed);
        Self
    }
}

impl Drop for CommitYieldGuard {
    fn drop(&mut self) {
        YIELD_DURING_COMMIT.store(false, Ordering::Relaxed);
    }
}

// SAFETY: This name is unique and accessed by assembly using a locked increment.
#[unsafe(no_mangle)]
static ostd_alt_runtime_trace_count: AtomicU64 = AtomicU64::new(0);

global_asm!(
    include_str!("../alternative_macros.S"),
    include_str!("test.S"),
    ".purgem OSTD_ALTERNATIVE",
    ".purgem OSTD_ALTERNATIVE_BRANCH",
    ".purgem OSTD_ALTERNATIVE_TAIL_CALL",
    ".purgem OSTD_ALTERNATIVE_CALL",
    ".purgem OSTD_ALTERNATIVE_DESCRIPTOR",
    branch_group_id = const AlternativeId::TestRuntimeBranch.as_raw(),
    tail_call_group_id = const AlternativeId::TestRuntimeTailCall.as_raw(),
    trace_group_id = const AlternativeId::TestRuntimeTrace.as_raw(),
);

unsafe extern "C" {
    fn ostd_alt_runtime_branch() -> u64;
    fn ostd_alt_runtime_tail_call(value: u64) -> u64;
    fn ostd_alt_runtime_old(value: u64) -> u64;
    fn ostd_alt_runtime_new(value: u64) -> u64;
    fn ostd_alt_runtime_check_trace(value: u64, alignment: usize) -> u64;
    fn ostd_alt_runtime_trace_trampoline();
}

#[inline(always)]
pub(super) fn record_breakpoint() {
    BREAKPOINT_COUNT.fetch_add(1, Ordering::Relaxed);
}

pub(super) fn exercise_instructions() {
    rust_sites::exercise_instructions();
    let state = EXERCISE_STATE.load(Ordering::Acquire);
    if state == EXERCISE_INACTIVE {
        return;
    }
    let increment = if state == EXERCISE_ORIGINAL { 1 } else { 42 };
    // SAFETY: These leaves keep the same ABI and are safe in interrupt context
    // under both configurations. The trace wrapper checks both stack alignments.
    unsafe {
        assert_eq!(ostd_alt_runtime_branch(), increment);
        assert_eq!(ostd_alt_runtime_tail_call(10), 10 + increment);
        assert_eq!(ostd_alt_runtime_check_trace(10, 0), 1);
        assert_eq!(ostd_alt_runtime_check_trace(10, 8), 1);
    }
    EXERCISE_COUNT.fetch_add(1, Ordering::Relaxed);
}

fn linked_table() -> AlternativeTable {
    // SAFETY: The running kernel passed OSDK validation; runtime commits do not
    // modify its immutable metadata or address mapping.
    unsafe { AlternativeTable::from_linked_image().unwrap() }
}

fn trace_enabled() -> AlternativeCallState {
    // SAFETY: This permanent assembly trampoline preserves registers and flags
    // and only updates its resident counter using an atomic instruction.
    AlternativeCallState::Enabled(unsafe {
        AlternativeCallTrampoline::new(ostd_alt_runtime_trace_trampoline as *const () as usize)
    })
}

fn enable_builder(table: &AlternativeTable) -> AlternativePatchBuilder<'_, AlternativeRuntime> {
    let mut builder = AlternativePatchBuilder::new(table);
    builder
        .set_branch(
            table.all::<groups::TestRuntimeBranch>(),
            AlternativeBranchState::Disabled,
            AlternativeBranchState::Enabled,
        )
        .unwrap();
    builder
        .retarget_tail_call(
            table.all::<groups::TestRuntimeTailCall>(),
            groups::TestRuntimeTailCall::target(ostd_alt_runtime_old),
            groups::TestRuntimeTailCall::target(ostd_alt_runtime_new),
        )
        .unwrap();
    builder
        .set_call(
            table.all::<groups::TestRuntimeTrace>(),
            AlternativeCallState::Disabled,
            trace_enabled(),
        )
        .unwrap();
    builder
}

fn disable_builder(table: &AlternativeTable) -> AlternativePatchBuilder<'_, AlternativeRuntime> {
    let mut builder = AlternativePatchBuilder::new(table);
    builder
        .set_branch(
            table.all::<groups::TestRuntimeBranch>(),
            AlternativeBranchState::Enabled,
            AlternativeBranchState::Disabled,
        )
        .unwrap();
    builder
        .retarget_tail_call(
            table.all::<groups::TestRuntimeTailCall>(),
            groups::TestRuntimeTailCall::target(ostd_alt_runtime_new),
            groups::TestRuntimeTailCall::target(ostd_alt_runtime_old),
        )
        .unwrap();
    builder
        .set_call(
            table.all::<groups::TestRuntimeTrace>(),
            trace_enabled(),
            AlternativeCallState::Disabled,
        )
        .unwrap();
    builder
}

#[ktest]
fn reversible_commits_execute_during_every_smp_phase() {
    let _lock = TEST_LOCK.lock();
    let table = linked_table();
    let cpus = crate::cpu::num_cpus();
    let passes = EXERCISE_COUNT.load(Ordering::Relaxed);
    let breakpoints = BREAKPOINT_COUNT.load(Ordering::Relaxed);
    let traces = ostd_alt_runtime_trace_count.load(Ordering::Relaxed);
    const ROUNDS: usize = 16;
    for _ in 0..ROUNDS {
        EXERCISE_STATE.store(EXERCISE_REPLACEMENT, Ordering::Release);
        // SAFETY: The test sites obey their ABI in every IRQ context, reside
        // permanently in writable text, and are independent of the patcher.
        assert_eq!(unsafe { enable_builder(&table).commit() }, Ok(3));
        EXERCISE_STATE.store(EXERCISE_ORIGINAL, Ordering::Release);
        // SAFETY: The reverse conversion has the same contracts as enabling.
        assert_eq!(unsafe { disable_builder(&table).commit() }, Ok(3));
    }
    EXERCISE_STATE.store(EXERCISE_INACTIVE, Ordering::Release);
    assert_eq!(
        EXERCISE_COUNT.load(Ordering::Relaxed) - passes,
        6 * cpus * ROUNDS
    );
    // Two INT3 rounds, four invocations per CPU, in both directions.
    assert_eq!(
        BREAKPOINT_COUNT.load(Ordering::Relaxed) - breakpoints,
        16 * cpus * ROUNDS
    );
    // Only enabling rounds call the trampoline, twice in each of three phases.
    assert_eq!(
        ostd_alt_runtime_trace_count.load(Ordering::Relaxed) - traces,
        (6 * cpus * ROUNDS) as u64
    );
    assert!(ACTIVE_PATCHES.load(Ordering::SeqCst).is_null());
    assert_eq!(BREAKPOINT_READERS.load(Ordering::SeqCst), 0);
}

#[ktest]
fn stale_runtime_batch_leaves_every_site_unchanged() {
    let _lock = TEST_LOCK.lock();
    let table = linked_table();
    let mut builder = enable_builder(&table);
    // Add a stale expectation on a separate boot-patched branch. Checking all
    // expectations must finish before the valid runtime sites are changed.
    builder
        .set_branch(
            table.all::<groups::TestBranch>(),
            AlternativeBranchState::Disabled,
            AlternativeBranchState::Enabled,
        )
        .unwrap();
    // SAFETY: The selected sites have permanent, ABI-compatible control targets.
    assert_eq!(
        unsafe { builder.commit() },
        Err(AlternativesError::UnexpectedInstruction)
    );
    let traces = ostd_alt_runtime_trace_count.load(Ordering::Relaxed);
    EXERCISE_STATE.store(EXERCISE_ORIGINAL, Ordering::Release);
    exercise_instructions();
    EXERCISE_STATE.store(EXERCISE_INACTIVE, Ordering::Release);
    assert_eq!(ostd_alt_runtime_trace_count.load(Ordering::Relaxed), traces);
    assert!(ACTIVE_PATCHES.load(Ordering::SeqCst).is_null());
}

#[ktest]
fn runtime_commit_rejects_disabled_irqs() {
    let _lock = TEST_LOCK.lock();
    let table = linked_table();
    let builder = enable_builder(&table);
    let irq_guard = crate::irq::disable_local();
    // SAFETY: Sites meet the live-patching contract; the checked context error
    // must be returned before any allocation, lock acquisition, or code write.
    assert_eq!(
        unsafe { builder.commit() },
        Err(AlternativesError::InvalidContext)
    );
    drop(irq_guard);
    assert!(ACTIVE_PATCHES.load(Ordering::SeqCst).is_null());
}

#[ktest]
fn overlapping_writers_check_expectations_under_the_same_lock() {
    let _lock = TEST_LOCK.lock();
    let _yield_guard = CommitYieldGuard::new();
    let start = Arc::new((WaitQueue::new(), AtomicUsize::new(0)));
    let finished = Arc::new((WaitQueue::new(), AtomicUsize::new(0)));
    let results = Arc::new(Mutex::new(Vec::new()));
    let active = Arc::new(AtomicUsize::new(0));
    let peak_active = Arc::new(AtomicUsize::new(0));
    const WRITERS: usize = 4;
    for _ in 0..WRITERS {
        let start = start.clone();
        let finished = finished.clone();
        let results = results.clone();
        let active = active.clone();
        let peak_active = peak_active.clone();
        task::TaskOptions::new(move || {
            let table = linked_table();
            let builder = enable_builder(&table);
            start
                .0
                .wait_until(|| (start.1.load(Ordering::Acquire) != 0).then_some(()));
            let count = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak_active.fetch_max(count, Ordering::SeqCst);
            // SAFETY: All writers use the commit protocol and the same permanent
            // test targets. Exactly one should observe the expected old bytes.
            let result = unsafe { builder.commit() };
            active.fetch_sub(1, Ordering::SeqCst);
            results.lock().push(result);
            finished.1.fetch_add(1, Ordering::Release);
            finished.0.wake_all();
        })
        .data(())
        .spawn()
        .unwrap();
    }
    start.1.store(1, Ordering::Release);
    start.0.wake_all();
    finished
        .0
        .wait_until(|| (finished.1.load(Ordering::Acquire) == WRITERS).then_some(()));
    let results = results.lock();
    assert_eq!(peak_active.load(Ordering::SeqCst), WRITERS);
    assert_eq!(results.iter().filter(|result| **result == Ok(3)).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(AlternativesError::UnexpectedInstruction))
            .count(),
        WRITERS - 1,
    );
    // SAFETY: Restore the same permanent sites through the runtime protocol.
    assert_eq!(unsafe { disable_builder(&linked_table()).commit() }, Ok(3));
}

#[ktest]
fn tasks_execute_while_runtime_sites_change() {
    let _lock = TEST_LOCK.lock();
    let _yield_guard = CommitYieldGuard::new();
    let table = linked_table();
    let progress = Arc::new((WaitQueue::new(), AtomicUsize::new(0)));
    let stop = Arc::new(atomic::AtomicBool::new(false));
    let failures = Arc::new(AtomicUsize::new(0));
    let finished = Arc::new((WaitQueue::new(), AtomicUsize::new(0)));
    const WORKERS: usize = 4;
    for _ in 0..WORKERS {
        let progress = progress.clone();
        let stop = stop.clone();
        let failures = failures.clone();
        let finished = finished.clone();
        task::TaskOptions::new(move || {
            while !stop.load(Ordering::Acquire) {
                // SAFETY: Both variants preserve the declared ABI, and the
                // writer keeps all bytes and callback dependencies resident.
                let (branch, call, trace) = unsafe {
                    (
                        ostd_alt_runtime_branch(),
                        ostd_alt_runtime_tail_call(10),
                        ostd_alt_runtime_check_trace(10, 0),
                    )
                };
                if !matches!(branch, 1 | 42) || !matches!(call, 11 | 52) || trace != 1 {
                    failures.fetch_add(1, Ordering::Relaxed);
                }
                progress.1.fetch_add(1, Ordering::Release);
                progress.0.wake_all();
                task::Task::yield_now();
            }
            finished.1.fetch_add(1, Ordering::Release);
            finished.0.wake_all();
        })
        .data(())
        .spawn()
        .unwrap();
    }
    progress
        .0
        .wait_until(|| (progress.1.load(Ordering::Acquire) != 0).then_some(()));
    for _ in 0..32 {
        let before = progress.1.load(Ordering::Acquire);
        // SAFETY: These test leaves support concurrent execution of both
        // configurations; all writers go through the runtime protocol.
        unsafe {
            assert_eq!(enable_builder(&table).commit(), Ok(3));
            assert_eq!(disable_builder(&table).commit(), Ok(3));
        }
        assert!(progress.1.load(Ordering::Acquire) > before);
    }
    stop.store(true, Ordering::Release);
    finished
        .0
        .wait_until(|| (finished.1.load(Ordering::Acquire) == WORKERS).then_some(()));
    assert_eq!(failures.load(Ordering::Relaxed), 0);
}
