// SPDX-License-Identifier: MPL-2.0

//! Group identities and the instruction contracts accepted by each group.
//!
//! The declaration below generates both dense ELF IDs and sealed Rust group
//! types. IDs identify groups of sites, not condition bits or individual sites.
//! Numbers are local to one kernel build and are not a stable module ABI.

use core::marker::PhantomData;

use super::alternative_macros::define_alternative_groups;

define_alternative_groups! {
    SpeculationBarrier: Sequence,
    #[cfg(ktest)] TestSequence: Sequence,
    #[cfg(ktest)] TestDisabled: Sequence,
    #[cfg(ktest)] TestEnabled: Sequence,
    #[cfg(ktest)] TestBranch: Branch,
    #[cfg(ktest)] TestTailCall: TailCall(unsafe extern "C" fn(u64) -> u64),
    #[cfg(ktest)] TestTrace: Call,
}

/// A group declared in the alternatives registry.
pub(in crate::arch) trait AlternativeGroup: sealed::Group {
    const ID: AlternativeId;
    type Kind: AlternativeKind;
}

/// An instruction contract supported by the descriptor format.
pub(in crate::arch) trait AlternativeKind: sealed::Kind {
    const TAG: AlternativeKindTag;
}

// These discriminants are the descriptor ABI shared with alternative_macros.S.
/// The checked instruction contract of an ELF descriptor.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::arch) enum AlternativeKindTag {
    Sequence = 0,
    Branch = 1,
    TailCall = 2,
    Call = 3,
}

impl AlternativeKindTag {
    pub(super) fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::Sequence),
            1 => Some(Self::Branch),
            2 => Some(Self::TailCall),
            3 => Some(Self::Call),
            _ => None,
        }
    }
}

/// A boot-only instruction sequence with a linked replacement.
pub(in crate::arch) enum AlternativeSequence {}
/// A NOP/JMP branch with a fixed destination.
pub(in crate::arch) enum AlternativeBranch {}
/// A retargetable JMP slot with the function signature declared by its group.
pub(in crate::arch) enum AlternativeTailCall {}
/// A NOP/CALL slot whose trampoline preserves the site's required execution state.
pub(in crate::arch) enum AlternativeCall {}

macro_rules! implement_kind {
    ($($kind:ident => $tag:ident),+ $(,)?) => {
        $(
            impl sealed::Kind for $kind {}
            impl AlternativeKind for $kind {
                const TAG: AlternativeKindTag = AlternativeKindTag::$tag;
            }
        )+
    };
}

implement_kind! {
    AlternativeSequence => Sequence,
    AlternativeBranch => Branch,
    AlternativeTailCall => TailCall,
    AlternativeCall => Call,
}

/// A function target constructed using its group's declared function signature.
pub(in crate::arch) struct AlternativeTailCallTarget<
    G: AlternativeGroup<Kind = AlternativeTailCall>,
> {
    address: usize,
    group: PhantomData<G>,
}

impl<G: AlternativeGroup<Kind = AlternativeTailCall>> AlternativeTailCallTarget<G> {
    pub(super) fn address(&self) -> usize {
        self.address
    }
}

/// A statically linked trampoline satisfying its selected call sites' ABI.
#[derive(Clone, Copy)]
pub(in crate::arch) struct AlternativeCallTrampoline {
    address: usize,
}

impl AlternativeCallTrampoline {
    /// Creates a handle to a permanently resident call trampoline.
    ///
    /// # Safety
    ///
    /// The address must denote an entry in the linked kernel text. It must
    /// preserve all registers, flags, and stack state required by every selected
    /// call site, and return to the instruction following the CALL.
    /// Its code and dependencies must remain valid for the kernel's lifetime.
    /// This constructor does not adapt an ordinary function to the site's ABI.
    #[cfg_attr(not(ktest), expect(dead_code))]
    pub(in crate::arch) unsafe fn new(address: usize) -> Self {
        Self { address }
    }

    pub(super) fn address(self) -> usize {
        self.address
    }
}

/// Returns the descriptor ID only for a registered sequence group.
#[cfg_attr(not(ktest), expect(dead_code))]
pub(super) const fn sequence_id<G: AlternativeGroup<Kind = AlternativeSequence>>() -> u32 {
    G::ID.as_raw()
}

mod sealed {
    pub(in crate::arch) trait Group {}
    pub(in crate::arch) trait Kind {}
}
