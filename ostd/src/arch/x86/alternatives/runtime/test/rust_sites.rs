// SPDX-License-Identifier: MPL-2.0

//! End-to-end tests of sites emitted inside Rust functions.

use core::{arch::naked_asm, hint::black_box};

use super::*;
use crate::arch::alternatives::{
    alternative_macros::{
        alternative_branch, alternative_call, alternative_tail_call_asm_template,
    },
    registry,
};

static CONFIGURATION: AtomicUsize = AtomicUsize::new(0);
static PHASE_EXECUTIONS: AtomicUsize = AtomicUsize::new(0);
static FIRST_CALLBACKS: AtomicUsize = AtomicUsize::new(0);
static SECOND_CALLBACKS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy)]
enum Configuration {
    Original = 1,
    FirstCallback = 2,
    SecondCallback = 3,
}

impl Configuration {
    fn branch(self) -> AlternativeBranchState {
        match self {
            Self::Original => AlternativeBranchState::Disabled,
            _ => AlternativeBranchState::Enabled,
        }
    }

    fn tail_call(self) -> registry::AlternativeTailCallTarget<groups::TestRustTailCall> {
        match self {
            Self::Original => groups::TestRustTailCall::target(old_target),
            _ => groups::TestRustTailCall::target(new_target),
        }
    }

    fn call(self) -> AlternativeCallState {
        let trampoline = match self {
            Self::Original => return AlternativeCallState::Disabled,
            Self::FirstCallback => first_trampoline,
            Self::SecondCallback => second_trampoline,
        };
        // SAFETY: Both resident trampolines preserve all GPRs and flags, align
        // the stack for their Rust callbacks, and return to the inline site.
        // OSTD's target disables compiler-generated floating-point/vector code.
        AlternativeCallState::Enabled(unsafe {
            AlternativeCallTrampoline::new(trampoline as *const () as usize)
        })
    }
}

struct CountDrop<'a>(&'a AtomicUsize);

impl Drop for CountDrop<'_> {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

// Inline this twice in check_sites: each expansion must retain its own slot and
// compiler-visible branch destination, including the early return's cleanup.
#[inline(always)]
fn branch_from_rust(value: u64, drops: &AtomicUsize) -> u64 {
    let _guard = CountDrop(drops);
    // SAFETY: Both Rust paths are valid in task and ordinary IRQ context. Only
    // this module patches the group, through the serialized runtime protocol.
    if unsafe { alternative_branch!(groups::TestRustBranch) } {
        return value.rotate_left(7);
    }
    value.wrapping_add(1)
}

/// Dispatches eight arguments through the patchable tail-call slot.
///
/// # Safety
///
/// The selected target must retain the registered signature and remain valid
/// during execution. Changes must use the runtime commit protocol.
// SAFETY: This function consists solely of a JMP to a Rust C-ABI target with
// exactly this signature. It preserves the return address and stack arguments.
#[unsafe(naked)]
unsafe extern "C" fn tail_call_from_rust(
    a: u64,
    b: u64,
    c: u64,
    d: u64,
    e: u64,
    f: u64,
    g: u64,
    h: u64,
) -> u64 {
    naked_asm!(
        alternative_tail_call_asm_template!(),
        alt_group_id = const registry::tail_call_id::<groups::TestRustTailCall>(),
        alt_destination = sym old_target,
    );
}

extern "C" fn old_target(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64) -> u64 {
    a.wrapping_add(b.wrapping_mul(2))
        .wrapping_add(c.wrapping_mul(3))
        .wrapping_add(d.wrapping_mul(4))
        .wrapping_add(e.wrapping_mul(5))
        .wrapping_add(f.wrapping_mul(6))
        .wrapping_add(g.wrapping_mul(7))
        .wrapping_add(h.wrapping_mul(8))
}

extern "C" fn new_target(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64) -> u64 {
    old_target(a, b, c, d, e, f, g, h).wrapping_add(42)
}

#[inline(never)]
fn call_from_rust(value: u64) -> u64 {
    // Keep computed Rust values alive across the site. The callback deliberately
    // clobbers caller-saved registers, so its trampoline must restore them.
    let (first, second, third, fourth) = black_box((
        value.wrapping_add(3),
        value.rotate_left(11),
        value ^ 0xfeed_face,
        value.wrapping_mul(17),
    ));
    // SAFETY: Every selected trampoline preserves registers, flags and the stack
    // and accesses only its own atomics. Both configurations support IRQ use.
    unsafe { alternative_call!(groups::TestRustCall) };
    first ^ second ^ third ^ fourth
}

// These are test adapters, not ordinary function-pointer targets: an inline
// call site requires preservation beyond the C ABI's callee-saved registers.
macro_rules! callback_trampoline {
    ($name:ident, $callback:ident) => {
        /// Calls a Rust callback while preserving the inline site's state.
        ///
        /// # Safety
        ///
        /// The caller must provide kernel stack space for the saved registers
        /// and callback and exclude execution from NMI/MCE handlers.
        // SAFETY: Save every caller-saved GPR and flags around the Rust call.
        // RBP anchors the saved stack while it is aligned; the callback obeys
        // the C ABI for the remaining registers and uses no floating-point/SIMD.
        #[unsafe(naked)]
        unsafe extern "C" fn $name() {
            naked_asm!(
                "pushfq",
                "push rax", "push rcx", "push rdx", "push rsi", "push rdi",
                "push r8", "push r9", "push r10", "push r11", "push rbp",
                "mov rbp, rsp",
                "and rsp, -16",
                "call {callback}",
                "mov rsp, rbp",
                "pop rbp", "pop r11", "pop r10", "pop r9", "pop r8",
                "pop rdi", "pop rsi", "pop rdx", "pop rcx", "pop rax",
                "popfq",
                "ret",
                callback = sym $callback,
            );
        }
    };
}

callback_trampoline!(first_trampoline, first_callback);
callback_trampoline!(second_trampoline, second_callback);

extern "C" fn first_callback() {
    FIRST_CALLBACKS.fetch_add(1, Ordering::Relaxed);
    clobber_callers();
}

extern "C" fn second_callback() {
    SECOND_CALLBACKS.fetch_add(1, Ordering::Relaxed);
    clobber_callers();
}

#[inline(always)]
fn clobber_callers() {
    // SAFETY: Only declared caller-saved GPRs and flags change. All memory and
    // stack state is preserved. This makes the trampoline test non-vacuous.
    unsafe {
        core::arch::asm!(
            "mov rax, 0x11", "mov rcx, 0x22", "mov rdx, 0x33",
            "mov rsi, 0x44", "mov rdi, 0x55", "mov r8, 0x66",
            "mov r9, 0x77", "mov r10, 0x88", "mov r11, 0x99", "stc",
            out("rax") _, out("rcx") _, out("rdx") _, out("rsi") _, out("rdi") _,
            out("r8") _, out("r9") _, out("r10") _, out("r11") _,
            options(nomem, nostack),
        );
    }
}

#[inline(never)]
fn check_sites(configuration: Configuration, value: u64) {
    let drops = AtomicUsize::new(0);
    let enabled = !matches!(configuration, Configuration::Original);
    let expected_branch_fn = |value: u64| {
        if enabled {
            value.rotate_left(7)
        } else {
            value.wrapping_add(1)
        }
    };
    assert_eq!(branch_from_rust(value, &drops), expected_branch_fn(value));
    let second_value = value ^ 0xabcd_1234;
    assert_eq!(
        branch_from_rust(second_value, &drops),
        expected_branch_fn(second_value)
    );
    assert_eq!(drops.load(Ordering::Relaxed), 2);

    let tail_result = {
        let _guard = CountDrop(&drops);
        // SAFETY: All three functions have the group's exact signature. The
        // last two arguments travel on the stack through the naked JMP wrapper.
        unsafe { tail_call_from_rust(value, 2, 3, 4, 5, 6, 7, 8) }
    };
    assert_eq!(
        tail_result,
        value.wrapping_add(if enabled { 245 } else { 203 })
    );
    assert_eq!(drops.load(Ordering::Relaxed), 3);
    let expected_call = value.wrapping_add(3)
        ^ value.rotate_left(11)
        ^ (value ^ 0xfeed_face)
        ^ value.wrapping_mul(17);
    assert_eq!(call_from_rust(value), expected_call);
}

pub(super) fn exercise_instructions() {
    let configuration = match CONFIGURATION.load(Ordering::Acquire) {
        0 => return,
        1 => Configuration::Original,
        2 => Configuration::FirstCallback,
        3 => Configuration::SecondCallback,
        _ => unreachable!(),
    };
    let value = PHASE_EXECUTIONS.fetch_add(1, Ordering::Relaxed) as u64;
    check_sites(configuration, value.wrapping_mul(0x1234_5678_9abc_def1));
}

fn transition(table: &AlternativeTable, expected: Configuration, desired: Configuration) {
    let mut builder = AlternativePatchBuilder::<AlternativeRuntime>::new(table);
    let mut count = table.sites::<groups::TestRustCall>().count();
    if matches!(expected, Configuration::Original) != matches!(desired, Configuration::Original) {
        builder
            .set_branch(
                table.all::<groups::TestRustBranch>(),
                expected.branch(),
                desired.branch(),
            )
            .unwrap();
        builder
            .retarget_tail_call(
                table.all::<groups::TestRustTailCall>(),
                expected.tail_call(),
                desired.tail_call(),
            )
            .unwrap();
        count += table.sites::<groups::TestRustBranch>().count()
            + table.sites::<groups::TestRustTailCall>().count();
    }
    builder
        .set_call(
            table.all::<groups::TestRustCall>(),
            expected.call(),
            desired.call(),
        )
        .unwrap();
    CONFIGURATION.store(desired as usize, Ordering::Release);
    // SAFETY: All sites and callbacks are resident, IRQ-safe and independent of
    // the patching/trap infrastructure. TEST_LOCK excludes other test writers.
    assert_eq!(unsafe { builder.commit() }, Ok(count));
    CONFIGURATION.store(0, Ordering::Release);
}

#[ktest]
fn rust_sites_execute_and_retarget_during_every_smp_phase() {
    let _lock = TEST_LOCK.lock();
    let table = linked_table();
    let cpus = crate::cpu::num_cpus();
    let passes = PHASE_EXECUTIONS.load(Ordering::Relaxed);
    let breakpoints = BREAKPOINT_COUNT.load(Ordering::Relaxed);
    let first = FIRST_CALLBACKS.load(Ordering::Relaxed);
    let second = SECOND_CALLBACKS.load(Ordering::Relaxed);
    assert!(table.sites::<groups::TestRustBranch>().count() >= 2);
    // Compile-check the naked wrapper itself against the registered signature.
    let _target = groups::TestRustTailCall::target(tail_call_from_rust);
    check_sites(Configuration::Original, u64::MAX);

    const ROUNDS: usize = 8;
    for round in 0..ROUNDS {
        for (expected, desired) in [
            (Configuration::Original, Configuration::FirstCallback),
            (Configuration::FirstCallback, Configuration::SecondCallback),
            (Configuration::SecondCallback, Configuration::Original),
        ] {
            transition(&table, expected, desired);
            // Exercise native instructions after publication has been retired.
            check_sites(desired, (round as u64).wrapping_sub(4));
        }
    }
    assert_eq!(
        PHASE_EXECUTIONS.load(Ordering::Relaxed) - passes,
        9 * cpus * ROUNDS
    );
    // Two INT3 phases: four executed sites on enable/disable, one on retarget.
    assert_eq!(
        BREAKPOINT_COUNT.load(Ordering::Relaxed) - breakpoints,
        18 * cpus * ROUNDS
    );
    assert_eq!(
        FIRST_CALLBACKS.load(Ordering::Relaxed) - first,
        (3 * cpus + 1) * ROUNDS
    );
    assert_eq!(
        SECOND_CALLBACKS.load(Ordering::Relaxed) - second,
        (3 * cpus + 1) * ROUNDS
    );
    assert!(ACTIVE_PATCHES.load(Ordering::SeqCst).is_null());
    assert_eq!(BREAKPOINT_READERS.load(Ordering::SeqCst), 0);
}
