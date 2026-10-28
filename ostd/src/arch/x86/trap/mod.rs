// SPDX-License-Identifier: MPL-2.0 OR MIT
//
// The original source code is from [trapframe-rs](https://github.com/rcore-os/trapframe-rs),
// which is released under the following license:
//
// SPDX-License-Identifier: MIT
//
// Copyright (c) 2020 - 2024 Runji Wang
//
// We make the following new changes:
// * Implement the `trap_handler` of Asterinas.
//
// These changes are released under the following license:
//
// SPDX-License-Identifier: MPL-2.0

//! Kernel trap handling.

pub(super) mod gdt;
pub(super) mod idt;
pub(super) mod syscall;

use super::cpu::context::GeneralRegs;
use crate::{
    arch::{
        cpu::context::CpuException,
        irq::{self as arch_irq, HwIrqLine},
    },
    cpu::PrivilegeLevel,
    irq,
    mm::fault::TrapFrameApi,
};

cfg_select! {
    feature = "cvm_guest" => {
        use tdx_guest::tdcall;
        use crate::arch::tdx_guest::TrapFrameWrapper;
    }
}

const BREAKPOINT_VECTOR: usize = 3;

/// Trap frame of kernel interrupt
///
/// # Trap handler
///
/// You need to define a handler function like this:
///
/// ```
/// // SAFETY: The name does not collide with other symbols.
/// #[unsafe(no_mangle)]
/// extern "sysv64" fn trap_handler(tf: &mut TrapFrame) {
///     match tf.trap_num {
///         3 => {
///             println!("TRAP: BreakPoint");
///             tf.rip += 1;
///         }
///         _ => panic!("TRAP: {:#x?}", tf),
///     }
/// }
/// ```
#[expect(missing_docs)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TrapFrame {
    // Pushed by 'trap.S'
    pub rax: usize,
    pub rbx: usize,
    pub rcx: usize,
    pub rdx: usize,
    pub rsi: usize,
    pub rdi: usize,
    pub rbp: usize,
    pub r8: usize,
    pub r9: usize,
    pub r10: usize,
    pub r11: usize,
    pub r12: usize,
    pub r13: usize,
    pub r14: usize,
    pub r15: usize,

    pub trap_num: usize,
    pub error_code: usize,

    // Pushed by CPU
    pub rip: usize,
    pub cs: usize,
    pub rflags: usize,
    pub rsp: usize,
    pub ss: usize,
}

// Be careful: This assertion is a **soundness** requirement.
//
// According to the System V AMD64 ABI, the stack pointer should be aligned to
// at least 16 bytes. The hardware will align the stack pointer to a 16-byte
// boundary for exceptions and interrupts ("In IA-32e mode, the RSP is aligned
// to a 16-byte boundary before pushing the stack frame"), so we only need to
// ensure the size of a `TrapFrame` is also aligned.
crate::const_assert!(size_of::<TrapFrame>().is_multiple_of(16));

impl TrapFrameApi for TrapFrame {
    fn set_instruction_pointer(&mut self, ip: usize) {
        self.rip = ip;
    }

    fn instruction_pointer(&self) -> usize {
        self.rip
    }
}

/// Initializes interrupt handling on x86_64.
///
/// This function will:
/// - Switch to a new, CPU-local [GDT].
/// - Switch to a new, CPU-local [TSS].
/// - Switch to a new, global [IDT].
/// - Enable the [`syscall`] instruction.
///
/// [GDT]: https://wiki.osdev.org/GDT
/// [IDT]: https://wiki.osdev.org/IDT
/// [TSS]: https://wiki.osdev.org/Task_State_Segment
/// [`syscall`]: https://www.felixcloutier.com/x86/syscall
///
/// # Safety
///
/// On the current CPU, this function must be called
/// - only once and
/// - before any trap can occur.
pub(crate) unsafe fn init_on_cpu() {
    // SAFETY: Since there's no traps, no preemption can occur.
    unsafe { gdt::init_on_cpu() };

    idt::init_on_cpu();

    // SAFETY:
    // 1. Since there's no traps, no preemption can occur.
    // 2. `gdt::init_on_cpu` has been called before.
    unsafe { syscall::init_on_cpu() };
}

/// Userspace context.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct RawUserContext {
    pub(super) general: GeneralRegs,
    pub(super) rflags: usize,
    pub(super) trap_num: usize,
    pub(super) error_code: usize,
}

/// Handles traps from kernel mode.
///
/// # Safety
///
/// `f` must describe the current kernel trap, with local IRQs disabled and
/// CPU-local state available. The caller must restore the possibly updated frame
/// when returning. For INT3, the frame must include the gap reserved by `trap.S`:
/// the saved RSP identifies the interrupted stack, and the word immediately below
/// it must be writable and disjoint from `f` for CALL emulation.
// SAFETY: The name does not collide with other symbols.
// The linker and final ELF checker exclude runtime sites from this entry path.
#[unsafe(link_section = ".text.alternatives_protected")]
#[unsafe(no_mangle)]
unsafe extern "sysv64" fn trap_handler(f: &mut TrapFrame) {
    // Handle patch breakpoints before dispatching general exceptions or IRQs.
    // This path must not enable IRQs, allocate, or acquire a lock.
    // SAFETY: The caller supplies a kernel INT3 frame with its emulation gap.
    if f.trap_num == BREAKPOINT_VECTOR && unsafe { super::alternatives::handle_breakpoint(f) } {
        return;
    }

    handle_kernel_trap(f);
}

// Keep general exception handling out of the protected breakpoint fast path.
#[inline(never)]
fn handle_kernel_trap(f: &mut TrapFrame) {
    fn enable_local_if(cond: bool) {
        if cond {
            arch_irq::enable_local();
        }
    }

    fn disable_local_if(cond: bool) {
        if cond {
            arch_irq::disable_local();
        }
    }

    // The IRQ state before trapping. We need to ensure that the IRQ state
    // during exception handling is consistent with the state before the trap.
    let was_irq_enabled =
        f.rflags as u64 & x86_64::registers::rflags::RFlags::INTERRUPT_FLAG.bits() > 0;

    let cpu_exception = CpuException::new(f.trap_num, f.error_code);
    match cpu_exception {
        #[cfg(feature = "cvm_guest")]
        Some(CpuException::VirtualizationException) => {
            let ve_info = tdcall::get_veinfo().expect("#VE handler: fail to get VE info\n");
            // We need to enable interrupts only after `tdcall::get_veinfo` is called
            // to avoid nested `#VE`s.
            enable_local_if(was_irq_enabled);
            let mut trapframe_wrapper = TrapFrameWrapper(&mut *f);
            tdx_guest::handle_virtual_exception(&mut trapframe_wrapper, &ve_info);
            *f = *trapframe_wrapper.0;
            disable_local_if(was_irq_enabled);
        }
        Some(page_fault @ CpuException::PageFault(raw_page_fault_info)) => {
            enable_local_if(was_irq_enabled);
            crate::mm::fault::handle_user_page_fault(f, &page_fault, raw_page_fault_info.addr);
            disable_local_if(was_irq_enabled);
        }
        Some(exception) => {
            enable_local_if(was_irq_enabled);
            panic!(
                "Cannot handle kernel CPU exception: {:#x?}; trapframe: {:#x?}",
                exception, f
            );
        }
        None => {
            irq::call_irq_callback_functions(
                f,
                &HwIrqLine::new(f.trap_num as u8),
                PrivilegeLevel::Kernel,
            );
        }
    }
}

/// User-space code segment selector value.
pub const USER_CS_VALUE: usize = gdt::USER_CS.0 as usize;
/// User-space stack segment selector value.
pub const USER_SS_VALUE: usize = gdt::USER_SS.0 as usize;
