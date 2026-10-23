// SPDX-License-Identifier: MPL-2.0

//! Typed instruction-patching requests over a common static site catalog.
//!
//! OSDK validates all `.altinstructions` records in the final ELF before image
//! packaging or running, even when Cargo reuses an existing ELF. The registry
//! assigns each group a dense ID and a sealed instruction contract. Sequence,
//! branch, tail-call, and call sites all use this table; IDs select
//! groups, while typed site handles permit selecting individual members.
//!
//! Owners submit requests through a mutable reference to a local
//! [`AlternativePatchBuilder`]. Its boot-only [`commit`](AlternativePatchBuilder::commit)
//! method consumes the builder, prepares its requests, and applies them before AP
//! startup. Batch preparation is internal and does not access executable bytes.
//! Missing requests leave sites unchanged; disabling requires an explicit reverse
//! conversion. There is no global condition bitmap or frozen policy.
//!
//! Control transfers carry expected bytes checked before any write. Arbitrary
//! sequences rely on the one-attempt boot contract because no original-byte
//! backup is retained.
//! A batch is neither a globally atomic transaction nor a rollback facility.
//!
//! Runtime builders accept control-transfer requests, but have no `commit`
//! method until SMP synchronization, INT3 handling, and target-lifetime
//! requirements are implemented. Phase types prevent using runtime requests
//! with the boot executor. Tracing tests use explicit assembly entries; compiler
//! instrumentation and dynamic log integration are not added.
//!
//! # Safety boundaries
//!
//! The registry macro emits `.altgroups` from the same cfg-filtered declaration
//! as the Rust IDs. OSDK checks descriptor layout, group/kind agreement, section
//! mappings and linker boundaries, lengths, ranges, non-overlapping slots, and
//! initial control instructions. Stripping and boot-header transformations must
//! preserve the checked sections. Custom build flows must provide the same check.
//!
//! [`AlternativeTable`] decodes this validated image; it does not repeat static
//! ELF validation at boot. Loading must preserve the validated address relations
//! and immutable metadata. Group and target constructors restrict requests; neither
//! Rust types nor structural checks prove instruction semantics or ABI compliance.
//! All unsafe writes and call-trampoline registration remain internal to OSTD.
//! Sequence replacements must obey the macro's position-independence constraints.
//!
//! The current production registry has no emitted sites. Kernel tests exercise
//! all four contracts through a single boot batch, then execute the patched
//! functions. Host checks cover macro layouts and compile-time API rejection.

mod alternative_macros;
mod encoding;
mod error;
mod patch;
pub(super) mod registry;
pub(super) mod request;
mod table;
#[cfg(ktest)]
mod test;

pub(super) use error::AlternativesError;
pub(super) use request::{AlternativeBoot, AlternativePatchBuilder};
pub(super) use table::AlternativeTable;
#[cfg(ktest)]
pub(super) use test::configure_test_alternatives;

const NOP_BYTE: u8 = 0x90;
