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
//! [`AlternativePatchBuilder`]. Its `commit` method consumes the builder and
//! applies its requests using the phase's protocol. Boot commits run before AP
//! startup. Batch preparation is internal and does not access executable bytes.
//! Missing requests leave sites unchanged; disabling requires an explicit reverse
//! conversion. There is no global condition bitmap or frozen policy.
//!
//! Control transfers carry expected bytes checked before any write. Arbitrary
//! sequences rely on the one-attempt boot contract because no original-byte
//! backup is retained.
//! A batch is neither a globally atomic transaction nor a rollback facility.
//!
//! Runtime commits accept only single-instruction, five-byte NOP/JMP/CALL
//! conversions. A mutex serializes writers, while temporary INT3 breakpoints
//! and three all-CPU instruction-serialization rounds protect execution. The
//! breakpoint handler emulates the desired instruction without blocking. Its
//! immutable batch metadata lives only until the last synchronization and reader
//! drain; no persistent per-site backup or version object is required.
//!
//! Callers must submit runtime commits from ordinary, sleepable task context
//! after SMP initialization; exception handlers are excluded by this contract.
//! Code targets and their dependencies remain resident: disabling a site does
//! not wait for old callbacks to finish. CPU hotplug and supervisor CET are not
//! supported. The patching and trap infrastructure must remain uninstrumented.
//! NMI/MCE handling and recovery are not implemented here; runtime sites must
//! not be reachable from those handlers. Ordinary IRQ execution is supported.
//! Tests cover assembly entries and explicit Rust branch/call sites; automatic
//! compiler instrumentation and dynamic log integration are not added.
//!
//! # Safety boundaries
//!
//! The registry macro emits `.altgroups` from the same cfg-filtered declaration
//! as the Rust IDs. OSDK checks descriptor layout, group/kind agreement, section
//! mappings and linker boundaries, lengths, ranges, non-overlapping slots, and
//! initial control instructions. Stripping and boot-header transformations must
//! preserve the checked sections. Custom build flows must provide the same check.
//! The runtime patching core and Rust breakpoint dispatch use the input section
//! `.text.alternatives_protected`, collected within `.text`. OSDK rejects runtime
//! slots overlapping its linker boundaries, while permitting boot-only sequences.
//! Entry/return assembly is not covered by this section. The unsafe commit
//! contract excludes selected sites from that assembly and all patching/trap
//! dependencies. The section check does not cover arbitrary compiler
//! instrumentation or callbacks that depend on the ongoing commit.
//!
//! [`AlternativeTable`] decodes this validated image; it does not repeat static
//! ELF validation at boot. Loading must preserve the validated address relations
//! and immutable metadata. Group and target constructors restrict requests; neither
//! Rust types nor structural checks prove instruction semantics or ABI compliance.
//! All unsafe writes and call-trampoline registration remain internal to OSTD.
//! Sequence replacements must obey the macro's position-independence constraints.
//!
//! The current production registry has no emitted sites. Kernel tests exercise
//! all four contracts at boot and reversible control transfers at runtime.
//! Host checks cover macro layouts and compile-time API rejection.

mod alternative_macros;
mod encoding;
mod error;
mod patch;
pub(super) mod registry;
pub(super) mod request;
mod runtime;
mod table;
#[cfg(ktest)]
mod test;

pub(super) use error::AlternativesError;
pub(super) use request::{AlternativeBoot, AlternativePatchBuilder};
pub(super) use runtime::handle_breakpoint;
pub(super) use table::AlternativeTable;
#[cfg(ktest)]
pub(super) use test::configure_test_alternatives;

const NOP_BYTE: u8 = 0x90;
