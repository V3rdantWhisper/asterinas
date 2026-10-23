// SPDX-License-Identifier: MPL-2.0

//! Rust and assembly frontends for emitting instruction slots and their metadata.
//!
//! Use [`alternative!`] for sequences without register operands.
//! For sequences with operands, wrap [`alternative_asm_template!`] in an operation-specific
//! function that owns the register declarations and both variants' side effects.
//! Both macros are internal to the alternatives subsystem.
//!
//! Assembly files use `OSTD_ALTERNATIVE` from `alternative_macros.S`.
//! Include it in the same `global_asm!` invocation as its consumer,
//! pass the group ID from Rust, and remove the assembler macro afterwards:
//!
//! ```rust,ignore
//! global_asm!(
//!     include_str!("alternative_macros.S"),
//!     include_str!("consumer.S"),
//!     ".purgem OSTD_ALTERNATIVE",
//!     group_id = const AlternativeId::SpeculationBarrier.as_raw(),
//! );
//! ```
//!
//! The consumer can then emit a slot with:
//!
//! ```asm
//! OSTD_ALTERNATIVE "", "lfence", {group_id}
//! ```
//!
//! Assembly consumers must uphold the same instruction and execution constraints
//! as Rust consumers and preserve their enclosing function's calling convention.

/// Emits a boot-time alternative without register operands.
///
/// The group must be a registered sequence group type; branch and call groups
/// are rejected at compile time.
/// Both variants use the default `asm!` effects, including memory accesses and changes to flags.
/// The macro does not expose operands or `options`.
///
/// ```rust,ignore
/// // SAFETY: Both variants preserve registers and the stack. This site cannot
/// // execute during patching, and LFENCE is available on all target CPUs.
/// unsafe {
///     alternative!("", "lfence", groups::SpeculationBarrier);
/// }
/// ```
///
/// # Safety
///
/// Both variants must obey the inline assembly rules without register operands:
/// they must not depend on incoming register values as inputs, must preserve
/// registers that would require output declarations, and must restore the stack.
/// Both must fall through and satisfy `alternative_asm_template!`'s constraints.
/// The original must be safe before patching, and the replacement must be safe
/// whenever its owner selects the replacement. Execution must not overlap patching.
#[cfg_attr(not(ktest), expect(unused_macros))]
macro_rules! alternative {
    ($old:literal, $new:literal, $group:ty $(,)?) => {
        ::core::arch::asm!(
            $crate::arch::alternatives::alternative_macros::alternative_asm_template!($old, $new),
            alt_group_id = const $crate::arch::alternatives::registry::sequence_id::<$group>(),
        )
    };
}

// The first consumers are the boot tests; production sites are added with their
// policies and execution-safety audits.
#[cfg_attr(not(ktest), expect(unused_imports))]
pub(super) use alternative;

/// Produces an assembly template for an automatically sized boot-time alternative.
///
/// Use this template inside `asm!`, supplying `alt_group_id` as a `const` operand.
/// Obtain the group ID with `AlternativeId::as_raw`, not a numeric literal.
/// The assembler sizes the slot to the longer sequence and pads the original with NOPs.
/// At least one sequence must be nonempty, and neither may exceed 65535 bytes.
/// The caller must declare the union of both variants' operands and side effects.
/// In particular, a memory barrier must not use `pure`, `nomem`, or `readonly`.
///
/// ```rust,ignore
/// let mut value = 10u64;
/// // SAFETY: Both variants only modify the declared RAX and flags.
/// // This site cannot execute during patching.
/// unsafe {
///     asm!(
///         alternative_asm_template!("add rax, 1", "add rax, 42"),
///         alt_group_id = const AlternativeId::SpeculationBarrier.as_raw(),
///         inout("rax") value,
///         options(nostack),
///     );
/// }
/// ```
///
/// # Instruction constraints
///
/// The replacement must be position independent:
/// no external relative branches, calls, or RIP-relative operands.
/// Labels 2 through 6 are reserved.
/// Each site and both variants must be audited together with the boot-time caller
/// of the patcher.
/// The macro does not make arbitrary instruction replacement safe.
#[cfg_attr(not(ktest), expect(unused_macros))]
macro_rules! alternative_asm_template {
    ($old:literal, $new:literal) => {
        concat!(
            "2:\n",
            $old,
            "\n3:\n",
            // GNU-style comparisons yield -1 for true. Pad by new_len - old_len
            // only when positive, as in Linux's x86 alternatives macros.
            ".skip -(((5f-4f)-(3b-2b)) > 0) * ((5f-4f)-(3b-2b)), 0x90\n",
            "6:\n",
            ".pushsection .altinstructions,\"a\",@progbits\n",
            ".balign 4\n",
            ".long 2b - .\n",
            ".long 4f - .\n",
            ".long {alt_group_id}\n",
            ".short 6b - 2b\n",
            ".short 5f - 4f\n",
            ".long 0\n", // AlternativeKindTag::Sequence.
            ".popsection\n",
            ".pushsection .altinstr_replacement,\"ax\",@progbits\n",
            ".code64\n",
            "4:\n",
            $new,
            "\n5:\n",
            // Unlike .if, .org is checked during layout, after padding and
            // relaxed instruction lengths resolve. An invalid slot makes it
            // move backwards by one byte, which the assembler rejects.
            ".org . + (((6b-2b) == 0) | ((6b-2b) > 65535))\n",
            ".popsection\n",
        )
    };
}

#[cfg_attr(not(ktest), expect(unused_imports))]
pub(super) use alternative_asm_template;

/// Defines dense IDs and sealed group types from one declaration.
///
/// Explicit C function-pointer signatures in tail-call declarations define the only
/// constructors of tail-call targets. Numeric discriminants and user implementations
/// are excluded. Call groups instead use an explicitly registered trampoline.
macro_rules! define_alternative_groups {
    ($($(#[cfg($cfg:meta)])? $name:ident: $kind:ident $(($($signature:tt)*))?,)+) => {
        #[repr(u32)]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub(in crate::arch) enum AlternativeId {
            $($(#[cfg($cfg)])? $name,)+
        }

        impl AlternativeId {
            pub(super) const ALL: &[Self] = &[
                $($(#[cfg($cfg)])? Self::$name,)+
            ];

            pub(super) const fn as_raw(self) -> u32 { self as u32 }

            pub(super) fn from_raw(raw: u32) -> Option<Self> {
                Self::ALL.get(raw as usize).copied()
            }

            pub(super) const fn kind(self) -> AlternativeKindTag {
                match self {
                    $($(#[cfg($cfg)])? Self::$name =>
                        <groups::$name as AlternativeGroup>::Kind::TAG,)+
                }
            }
        }

        // OSDK reads this build-specific registry from the final ELF. Generate
        // it here so cfg filtering and enum numbering cannot drift apart.
        // SAFETY: The linker keeps this immutable array in a read-only section.
        #[unsafe(link_section = ".altgroups")]
        #[used]
        static ALTERNATIVE_GROUP_KINDS: [u32; 3 + AlternativeId::ALL.len()] = {
            let mut words = [0; 3 + AlternativeId::ALL.len()];
            words[0] = 1; // Metadata format version.
            words[1] = 20; // Descriptor size in bytes.
            words[2] = AlternativeId::ALL.len() as u32;
            let mut index = 0;
            while index < AlternativeId::ALL.len() {
                words[3 + index] = AlternativeId::ALL[index].kind() as u32;
                index += 1;
            }
            words
        };

        pub(in crate::arch) mod groups {
            use super::*;
            $(
                $(#[cfg($cfg)])?
                pub(in crate::arch) enum $name {}

                $(#[cfg($cfg)])?
                impl sealed::Group for $name {}

                $(#[cfg($cfg)])?
                impl AlternativeGroup for $name {
                    const ID: AlternativeId = AlternativeId::$name;
                    type Kind = define_alternative_groups!(@kind $kind);
                }

                $(#[cfg($cfg)])?
                define_alternative_groups!(@target $name, $kind $(($($signature)*))?);
            )+
        }
    };
    (@kind Sequence) => { AlternativeSequence };
    (@kind Branch) => { AlternativeBranch };
    (@kind TailCall) => { AlternativeTailCall };
    (@kind Call) => { AlternativeCall };
    (@target $name:ident, TailCall(extern "C" fn($($argument:ty),* $(,)?) -> $result:ty)) => {
        define_alternative_groups!(@function_target $name, extern "C" fn($($argument),*) -> $result);
    };
    (@target $name:ident, TailCall(unsafe extern "C" fn($($argument:ty),* $(,)?) -> $result:ty)) => {
        define_alternative_groups!(@function_target $name, unsafe extern "C" fn($($argument),*) -> $result);
    };
    (@target $name:ident, TailCall(extern "C" fn($($argument:ty),* $(,)?))) => {
        define_alternative_groups!(@function_target $name, extern "C" fn($($argument),*));
    };
    (@target $name:ident, TailCall(unsafe extern "C" fn($($argument:ty),* $(,)?))) => {
        define_alternative_groups!(@function_target $name, unsafe extern "C" fn($($argument),*));
    };
    (@function_target $name:ident, $signature:ty) => {
        impl $name {
            /// Creates a target with this group's declared function signature.
            pub(in crate::arch) fn target(target_fn: $signature) -> AlternativeTailCallTarget<Self> {
                AlternativeTailCallTarget { address: target_fn as usize, group: PhantomData }
            }
        }
    };
    (@target $name:ident, $kind:ident) => {};
}

pub(super) use define_alternative_groups;
