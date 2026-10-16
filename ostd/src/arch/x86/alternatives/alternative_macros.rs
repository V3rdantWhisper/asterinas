// SPDX-License-Identifier: MPL-2.0

/// Emits a boot-time alternative without register operands.
///
/// The condition must be a constant `AlternativeId`. Both variants use the
/// default `asm!` effects, including memory accesses and changes to flags.
///
/// # Safety
///
/// Both variants must obey the inline assembly rules without register operands:
/// they must not depend on incoming register values as inputs, must preserve
/// registers that would require output declarations, and must restore the stack.
/// Both must fall through and satisfy `alternative_asm_template!`'s constraints.
/// The original must be safe before patching, and the replacement must be safe
/// whenever the condition is enabled. Execution must not overlap patching.
#[cfg_attr(not(ktest), expect(unused_macros))]
macro_rules! alternative {
    ($old:literal, $new:literal, $condition_id:expr $(,)?) => {
        ::core::arch::asm!(
            $crate::arch::alternatives::alternative_macros::alternative_asm_template!($old, $new),
            alt_condition_id = const $crate::arch::alternatives::condition::AlternativeId::as_raw(
                $condition_id,
            ),
        )
    };
}

// The first consumers are the boot tests; production sites are added with their
// policies and execution-safety audits.
#[cfg_attr(not(ktest), expect(unused_imports))]
pub(super) use alternative;

/// Produces an assembly template for an automatically sized boot-time alternative.
///
/// Use this template inside `asm!`, supplying `alt_condition_id` as a `const` operand.
/// Obtain the condition ID with `AlternativeId::as_raw`, not a numeric literal.
/// The assembler sizes the slot to the longer sequence and pads the original with NOPs.
/// At least one sequence must be nonempty, and neither may exceed 65535 bytes.
/// The caller must declare the union of both variants' operands and side effects.
/// In particular, a memory barrier must not use `pure`, `nomem`, or `readonly`.
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
            ".long {alt_condition_id}\n",
            ".short 6b - 2b\n",
            ".short 5f - 4f\n",
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

/// Defines dense condition IDs and their checked conversion from ELF metadata.
///
/// Keeping the enum and list in one declaration makes their order and conditional
/// compilation agree. Explicit discriminants are deliberately unsupported.
macro_rules! define_alternative_ids {
    ($visibility:vis enum AlternativeId {
        $( $(#[cfg($cfg:meta)])? $name:ident, )+
    }) => {
        /// A boot-time condition shared by any number of instruction slots.
        #[repr(u32)]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        $visibility enum AlternativeId {
            $( $(#[cfg($cfg)])? $name, )+
        }

        impl AlternativeId {
            pub(super) const ALL: &[Self] = &[
                $( $(#[cfg($cfg)])? Self::$name, )+
            ];
            pub(super) const COUNT: usize = Self::ALL.len();

            pub(super) const fn as_raw(self) -> u32 {
                self as u32
            }

            pub(super) fn from_raw(raw: u32) -> Option<Self> {
                Self::ALL.get(raw as usize).copied()
            }
        }
    };
}

pub(super) use define_alternative_ids;
