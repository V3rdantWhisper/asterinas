# x86 Boot Alternatives

OSTD's internal x86 alternatives mechanism replaces instruction slots sized by the assembler
once during BSP initialization, before starting APs.
It provides the mechanism for future CPU-specific sequences;
the current conditions do not select vulnerability mitigations.
The initial consumers are kernel-test functions, not syscall or exception entries.

## Emitting a slot

The Rust `alternative!` macro emits a complete inline assembly block
for sequences without register inputs or outputs.
The caller supplies the original instructions, replacement instructions,
and a constant `AlternativeId`:

```rust,ignore
// SAFETY: Both variants preserve registers and the stack. This site cannot
// execute during patching, and LFENCE is available on all target CPUs.
unsafe {
    alternative!("", "lfence", AlternativeId::Always);
}
```

The macro retains the default `asm!` effects, including memory accesses
and changes to flags.
It does not expose operands or `options`.
The condition is checked as an `AlternativeId` in a constant context;
numeric literals and runtime values are rejected.
The macro requires an `unsafe` caller, which must ensure that both variants
obey the inline assembly rules without register operands.
In particular, they cannot depend on incoming register values as inputs,
must preserve registers that would require output declarations,
and must restore the stack and fall through.

For sequences with inputs or outputs, the internal `alternative_asm_template!`
macro produces only the assembly template.
Its caller supplies `alt_condition_id` as a constant operand
and declares the operands and side effects of **both** variants.
For example, the arithmetic tests use:

```rust,ignore
// SAFETY: Both variants only modify the declared RAX and flags. This site
// cannot execute during patching.
unsafe {
    asm!(
        alternative_asm_template!("add rax, 1", "add rax, 42"),
        alt_condition_id = const AlternativeId::Always.as_raw(),
        inout("rax") value,
        options(nostack),
    );
}
```

Specific operations that need registers should wrap this template in a function
that owns the operand declarations and exposes only the operation's parameters.
Both macro interfaces remain internal to the alternatives subsystem
until production consumers require wider visibility.
The condition IDs and update functions are available to policy owners within
the x86 architecture module.

For assembly files, include `alternatives/alternative_macros.S` in the same `global_asm!`
invocation as the source using it, then remove the assembler macro:

```rust,ignore
global_asm!(
    include_str!("alternatives/alternative_macros.S"),
    include_str!("consumer.S"),
    ".purgem OSTD_ALTERNATIVE",
    condition_id = const AlternativeId::Always.as_raw(),
);
```

The corresponding assembly site is:

```asm
OSTD_ALTERNATIVE "", "lfence", {condition_id}
```

Both frontends emit:

```text
.text                      .altinstructions                 .altinstr_replacement
[original + NOP padding] <- target_offset_bytes              [replacement bytes]
                           replacement_offset_bytes ------->
                           condition_id: u32
                           slot_len_bytes: u16
                           replacement_len_bytes: u16
```

Each `AlternativeDescriptor` is 16 bytes, aligned to 4 bytes.
Each signed 32-bit offset is relative to its own field, not the descriptor's start.
The assembler computes both sequence lengths from label differences
and sizes the slot to `max(original_len, replacement_len)`.
It pads the original with NOPs when the replacement is longer;
the replacement section stores only the replacement bytes.
Either sequence may be empty, but they cannot both be empty.
The slot must contain between 1 and 65535 bytes.
A layout-time `.org` check rejects empty or oversized slots,
preventing truncated lengths in the descriptor's `u16` fields from reaching the kernel.
A false condition retains the original bytes.
A true condition copies the replacement and pads the rest with NOPs.

The linker retains both metadata sections.
They are not reclaimed after boot.
Replacement bytes must not require relocation:
external relative branches, calls, and RIP-relative operands are unsupported.
Inline assembly must not use reserved labels 2 through 6,
or omit side effects of a possible replacement.
Memory barriers must not declare `pure`, `nomem`, or `readonly`.

## Selecting conditions and applying patches

The BSP calls `alternatives::apply_on_bsp()` before starting APs.
The module root coordinates the one-shot operation.
`condition.rs` owns the condition IDs, incremental updates, and the frozen bitmap;
`table.rs` owns the descriptor ABI, linker section boundaries, and validation;
`patch.rs` writes the validated patches, verifies their bytes, and serializes execution.
This separation keeps table validation free of instruction writes.

The private `ALTERNATIVE_ID_MAP` is a `spin::Once<AlternativeIdMap>`.
Before patching, each policy owner records its decisions independently through
`alternatives::enable_condition(id)` or `alternatives::disable_condition(id)`.
For example, a mitigation's `apply` method can enable its condition after it has
chosen and configured that mitigation, without editing a central policy match.
These functions only update the pending bitmap; they do not patch instructions
or configure hardware registers.
All conditions start disabled except `Always`, which cannot be disabled.

The pending bitmap is protected by one `SpinLock` with local IRQs disabled.
Updates and freezing use the same lock, so checking whether selection is still
open and changing a bit form one critical section.
The BSP removes the pending map and publishes it before validating any descriptor.
After removal, updates return `AlternativeUpdateError::Frozen`, including the
interval before the immutable snapshot has been published.
Disabling `Always` before freezing returns `AlternativeUpdateError::AlwaysEnabled`.
After publication, readers query the frozen bitmap without taking the update lock.

Repeated enabling or disabling is harmless; the last successful update to an ID wins.
Each ID should have one policy owner, even when several instruction sites share it.
All policy owners must finish their `apply` methods before
`alternatives::apply_on_bsp()` runs and before AP startup.
The update functions are for boot initialization, not NMI or exception handlers.
The current checkout has test policy owners; production mitigation implementations
will call the same update interface when they are added.
Several sites with different instruction encodings can share the same condition.

The boot sequence is:

```text
Policy A::apply() -> enable_condition(A)
Policy B::apply() -> disable_condition(B)
All remaining policy owners finish their updates
    |
    v
alternatives::apply_on_bsp()
    freeze_on_bsp() -> publish the immutable bitmap
    validate_linked_alternatives() -> prepare all patches
    commit_patches() -> write, verify, and serialize
    |
    v
Start APs
```

The caller must arrange this order;
the update interface does not discover or invoke policy owners.
The current call to `apply_on_bsp()` is in `arch/x86/mod.rs::late_init_on_bsp()`,
after timer initialization and before `boot_all_aps()`.
New policy initialization must complete before that call.
Publication records the selection policy, not completion of patching.
Calling `disable_condition` cannot undo instructions that have already been replaced.

The patcher checks the entire table before writing anything:

- Record layout, lengths, checked relative addresses, and section bounds.
- Valid condition IDs, including at disabled sites.
- Non-overlapping target slots.

Instruction bytes come from the linked image, without a separate byte-template registry.
Each site must audit both instruction sequences and their condition.
Byte-template assertions for the test sites stay in the tests.

Preparation allocates the validated `AlternativePatch` list,
whose `target_range` and `replacement_range` identify the instruction byte ranges.
Commit disables local IRQs, writes selected slots, verifies the bytes,
and executes a serializing CPUID before restoring the previous IRQ state.
Repeated attempts, including retries after validation failure, are rejected.
An error stops boot; the implementation does not roll back.

The current kernel mapping is writable and executable.
This implementation uses that mapping without changing page permissions or CR0.WP.
A future permission split must update this backend
before making the text mapping read-only.
Likewise, `Once` provides immutable Rust access to the bitmap,
not hardware read-only protection against arbitrary writes.

## Adding a condition

For another site using an existing policy, reuse its `AlternativeId`.
For a new policy, add a name to the `define_alternative_ids!` invocation in `condition.rs`
and have its policy owner's `apply` method call the appropriate update function.
The condition need not represent a mitigation:
a CPU feature or another boot-time decision can use the same interface.
Choose a name for the condition being selected, rather than for each patched function.
For example, after adding `MyMitigation` to the registry:

```rust,ignore
use crate::arch::alternatives::{self, AlternativeId, AlternativeUpdateError};

impl MyMitigation {
    fn apply(&self) -> Result<(), AlternativeUpdateError> {
        if self.is_enabled() {
            alternatives::enable_condition(AlternativeId::MyMitigation)?;
        } else {
            alternatives::disable_condition(AlternativeId::MyMitigation)?;
        }
        Ok(())
    }
}
```

This is the condition-selection part of a mitigation's `apply` method;
the mitigation remains responsible for any required hardware setup and CPU checks.
An error from the update interface must not be ignored: it means the requested
selection was not recorded, so initialization must stop or propagate the error.
The registry macro does not accept explicit numeric assignments.
It generates the enum, the valid ID list, the count, and checked integer conversion
from one declaration, including the same configuration attributes.
Duplicate names remain compile errors.
There is no central exhaustive policy match: an ID that its owner does not enable
stays disabled, so each new policy needs a test that verifies its selected conditions.
The bitmap uses a fixed array of `u64` words sized from the generated count,
so adding the 65th condition automatically adds a second word without heap allocation.

Pass an `AlternativeId` directly to `alternative!`.
For the low-level template, use `AlternativeId::as_raw()` for Rust assembly operands,
and pass the same constants through `global_asm!` to assembly files.
Do not maintain separate numeric definitions in assembly.
The descriptor retains a `u32` field, which is checked against the valid ID list
before querying the bitmap; an unknown ID stops boot.
The numbers are internal to one kernel build and are not a stable module ABI.
Changing the declaration order or configuration can change them.

The current `Always` condition selects every associated replacement.
The `TestDisabled` and `TestEnabled` conditions exist only under `cfg(ktest)`.
Future policies may combine CPU capabilities, boot configuration,
mitigation decisions, or virtualization state before the bitmap is frozen.
CPU-dependent choices must be supported by every CPU that can execute those sites;
detecting a feature on the BSP alone does not establish that guarantee.

## Execution safety

Instruction writes are not atomic.
The caller must establish that no CPU or handler can execute a target slot during commit.
APs have not started, and the IRQ guard excludes maskable interrupts.
Neither fact excludes NMI, MCE, or synchronous faults.
The current test-only sites are not called by any of those handlers or by the patching path.
Adding an entry-path site requires a separate reachability audit
and an appropriate execution exclusion mechanism;
this engine alone does not make patching exception entries safe.

The patcher and raw metadata stay inside OSTD.
There is no safe kernel API for writing arbitrary instructions
or choosing arbitrary target addresses.

## Validation

Use the repository's development container and pinned Rust toolchain:

```sh
python3 tools/check_x86_alternatives.py
make install_osdk
cd ostd
cargo osdk test patched_instructions_execute
cargo osdk test
SMP=4 QEMU_DISPLAY=none CONSOLE=ttyS0 NETDEV=none \
    cargo osdk test --release --qemu-args='-enable-kvm -cpu host'
```

The release command uses four virtual CPUs and requires KVM in the container.
Run the `cargo osdk test` commands from `ostd`:
OSDK builds a dedicated test kernel containing OSTD and the test runner,
then boots it in QEMU.
The tests execute in kernel mode without starting the full Asterinas kernel
or its user-space services.

The test modules use `#[cfg(ktest)] mod test`:
`alternatives/test.rs` and its included `test.S` exercise real instruction slots,
`condition/test.rs` checks condition selection,
and `table/test.rs` checks private descriptor validation.
These tests and their instruction slots are included in the kernel-test ELF
and excluded from an ordinary kernel build.

During test-kernel startup, `apply_on_bsp()` calls
`test::check_original_instructions()` and `test::configure_conditions()`
before freezing the bitmap and patching.
After initialization, the test runner invokes the selected `#[ktest]` functions,
including `patched_instructions_execute` and `frozen_conditions_reject_updates`.
Filtering the tests does not skip the earlier boot-time checks or patching.
Tests cover Rust and assembly sites, multiple expansions in one assembly block,
individually enabled and disabled conditions, inserting/removing LFENCE, tail padding,
shared conditions with different instruction sequences, and invalid metadata or IDs.
They also verify idempotent updates, independence of bits sharing a word,
rejection of updates after freezing, and preservation of the `Always` condition.
Patching always happens before AP startup, even though ordinary kernel tests run later.
The host-side assembler checks exercise both frontends at optimization levels 0 and 3.
They inspect linked descriptors, instruction bytes, and NOP padding
for equal lengths, growing/shrinking replacements, insertion/removal,
repeated expansions, local branches, and maximum lengths.
They reject empty slots and sequences exceeding 65535 bytes,
check condition numbering across configurations and a bitmap word boundary,
and reject duplicate names, explicit numbering, and untyped IDs.
The simple Rust interface is checked for typed constant conditions, macro hygiene,
repeated expansions, default memory and flag effects, and required `unsafe` use.
