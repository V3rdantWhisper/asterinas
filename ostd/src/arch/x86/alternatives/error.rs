// SPDX-License-Identifier: MPL-2.0

/// A failure to decode, prepare, or apply alternative instructions.
#[derive(Debug, PartialEq)]
pub(in crate::arch) enum AlternativesError {
    AlreadyAttempted,
    AddressOverflow,
    OutsideText,
    UnknownGroup,
    InvalidKind,
    ForeignTable,
    EmptySelection,
    ConflictingRequests,
    DisplacementOutOfRange,
    UnexpectedInstruction,
    OverlappingSlots,
    VerificationFailed,
    InvalidContext,
    RuntimeUnavailable,
    PatchingPoisoned,
}
