#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0

"""Check alternatives assembly, group IDs, and typed patch requests with the pinned Rust toolchain."""

import json
from pathlib import Path
import struct
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
MACROS = ROOT / "ostd/src/arch/x86/alternatives"


def generate_harness(entries, body, *, builder=False):
    # Use the actual registry implementation, replacing only its declaration so
    # boundary/cfg cases do not require adding synthetic production groups.
    registry = (MACROS / "registry.rs").read_text()
    start = registry.index("define_alternative_groups! {")
    end = registry.index("\n}", start) + 2
    registry = registry[:start] + "define_alternative_groups! {\n" + entries + "\n}" + registry[end:]
    modules = ""
    support = ""
    if builder:
        modules = f"""
const NOP_BYTE: u8 = 0x90;
#[path = {json.dumps(str(MACROS / 'error.rs'))}]
mod error;
use error::AlternativesError;
"""
        # These harnesses only emit Rust metadata; they never execute commit.
        # Compile the real writer with stand-ins for kernel IRQ and logging APIs.
        support = """
mod irq { pub(crate) fn disable_local() {} }
#[macro_export]
macro_rules! debug {
    ($($args:tt)*) => { let _ = core::format_args!($($args)*); };
}
"""
        for module in ("encoding", "table", "request", "patch"):
            source = (MACROS / f"{module}.rs").read_text()
            source = source.replace("#[cfg(ktest)]\nmod test;", "")
            modules += f"mod {module} {{\n{source}\n}}\n"
    return f"""
extern crate alloc;
{support}
mod arch {{
    mod alternatives {{
        #[path = {json.dumps(str(MACROS / 'alternative_macros.rs'))}]
        mod alternative_macros;
        mod registry {{ {registry} }}
        {modules}
        use registry::{{AlternativeId, groups}};
        {body}
    }}
    pub fn run() {{ alternatives::run(); }}
}}
fn main() {{ arch::run(); }}
"""


def generate_id_registry_source(entries, body):
    return generate_harness(entries, body.replace("fn main()", "pub(super) fn run()"))


def check_id_registry(directory):
    # Exercise a large registry and put a conditional ID in the middle,
    # so cfg changes must affect both enum numbering and the generated list.
    entries = [f"Group{index}: Sequence," for index in range(65)]
    entries.insert(10, "#[cfg(ktest)] TestGroup: Branch,")
    body = """
fn main() {
    assert_eq!(AlternativeId::ALL.len(), if cfg!(ktest) { 66 } else { 65 });
    for (index, &id) in AlternativeId::ALL.iter().enumerate() {
        assert_eq!(id.as_raw() as usize, index);
        assert_eq!(AlternativeId::from_raw(index as u32), Some(id));
    }
    assert_eq!(AlternativeId::from_raw(AlternativeId::ALL.len() as u32), None);
    assert_eq!(AlternativeId::from_raw(u32::MAX), None);
}
"""
    rust_source = directory / "registry.rs"
    rust_source.write_text(generate_id_registry_source("\n".join(entries), body))
    for configuration in ([], ["--cfg=ktest"]):
        executable = directory / "registry"
        result = subprocess.run(
            ["rustc", "--edition=2024", "-Clink-dead-code", *configuration, str(rust_source),
             "-o", str(executable)],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"group registry: {result.stderr}")
        subprocess.run([str(executable)], check=True)
        registry_dump = directory / "altgroups.bin"
        subprocess.run(
            ["objcopy", "--dump-section", f".altgroups={registry_dump}", str(executable)],
            capture_output=True, check=True,
        )
        count = 66 if configuration else 65
        kinds = [0] * count
        if configuration:
            kinds[10] = 1
        assert registry_dump.read_bytes() == struct.pack(f"<{3 + count}I", 1, 20, count, *kinds)
        print(f"PASS: group IDs, ktest={bool(configuration)}, dense numbering and ELF registry")

    cases = [
        ("duplicate-name", "First: Sequence, First: Sequence,", "fn main() {}", "E0428"),
        ("explicit-number", "First = 7: Sequence,", "fn main() {}", "no rules expected"),
        ("integer-tail-call-signature", "First: TailCall(u64),", "fn main() {}", "no rules expected"),
        ("untyped-id", "First: Sequence,", """
fn is_enabled(_: AlternativeId) -> bool { true }
fn main() { is_enabled(0u32); }
""", "E0308"),
    ]
    for name, entries, body, diagnostic in cases:
        rust_source.write_text(generate_id_registry_source(entries, body))
        result = subprocess.run(
            ["rustc", "--edition=2024", str(rust_source),
             "-o", str(directory / "registry")],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        if result.returncode == 0 or diagnostic not in result.stderr:
            raise RuntimeError(f"group IDs, {name}: unexpected result\n{result.stderr}")
        print(f"PASS: group IDs, {name} rejected")


def generate_test_source(frontend, sites):
    if frontend == "rust":
        templates = "\n".join(
            f"alternative_macros::alternative_asm_template!({json.dumps(old)}, {json.dumps(new)}),"
            for old, new, _, _ in sites
        )
        return f"""
#![no_std]
#[path = {json.dumps(str(MACROS / 'alternative_macros.rs'))}]
mod alternative_macros;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn test_alternative() {{
    unsafe {{ core::arch::asm!(
        {templates}
        alt_group_id = const 1,
        out("rax") _,
        options(nostack),
    ); }}
}}
"""
    templates = "\n".join(
        f'OSTD_ALTERNATIVE "{old}", "{new}", 1'
        for old, new, _, _ in sites
    )
    assembly = f"""
.text
.code64
.global test_alternative
.type test_alternative, @function
test_alternative:
    {templates}
    ret
.size test_alternative, .-test_alternative
.purgem OSTD_ALTERNATIVE
.purgem OSTD_ALTERNATIVE_BRANCH
.purgem OSTD_ALTERNATIVE_TAIL_CALL
.purgem OSTD_ALTERNATIVE_CALL
.purgem OSTD_ALTERNATIVE_DESCRIPTOR
"""
    return f"""
#![no_std]
core::arch::global_asm!(
    include_str!({json.dumps(str(MACROS / 'alternative_macros.S'))}),
    {json.dumps(assembly)},
);
"""


def check_linked_slots(directory, sites):
    executable = directory / "check.elf"
    subprocess.run(
        ["ld", "-e", "test_alternative", str(directory / "check.o"),
         "-o", str(executable)],
        capture_output=True, text=True, check=True,
    )
    # Linking resolves the field-relative offsets, so verify their targets as
    # well as the lengths. Use binutils to read the sections without an ELF parser.
    headers = subprocess.check_output(["objdump", "-h", str(executable)], text=True)
    sections = {}
    dump_command = ["objcopy"]
    for line in headers.splitlines():
        fields = line.split()
        if len(fields) < 7 or fields[1] not in (
            ".text", ".altinstructions", ".altinstr_replacement"
        ):
            continue
        name = fields[1]
        destination = directory / (name + ".bin")
        sections[name] = (int(fields[3], 16), destination)
        dump_command.extend(["--dump-section", f"{name}={destination}"])
    subprocess.run([*dump_command, str(executable)], capture_output=True, check=True)
    sections = {
        name: (address, path.read_bytes())
        for name, (address, path) in sections.items()
    }
    table_address, table = sections[".altinstructions"]
    text_address, text = sections[".text"]
    replacement_address, replacements = sections.get(".altinstr_replacement", (0, b""))
    assert len(table) == len(sites) * 20
    assert replacements == b"".join(new for _, _, _, new in sites)
    previous_end = None
    for index, (_, _, old, new) in enumerate(sites):
        target_offset, replacement_offset, group, slot_len, replacement_len, kind = (
            struct.unpack_from("<iiIHHI", table, index * 20)
        )
        assert group == 1
        assert kind == 0
        assert slot_len == max(len(old), len(new))
        assert replacement_len == len(new)
        target = table_address + index * 20 + target_offset
        if previous_end is not None:
            assert target == previous_end
        previous_end = target + slot_len
        text_offset = target - text_address
        assert 0 <= text_offset <= len(text) - slot_len
        assert text[text_offset:text_offset + slot_len] == old + b"\x90" * (slot_len - len(old))
        if replacement_len:
            source = table_address + index * 20 + 4 + replacement_offset - replacement_address
            assert 0 <= source <= len(replacements) - replacement_len
            assert replacements[source:source + replacement_len] == new


def check_rust_interface(directory):
    nop = b"\x90"
    lfence = b"\x0f\xae\xe8"
    cases = [
        ("typed-group", 'unsafe { alternative!("", "lfence", groups::Second); }',
         [("", "lfence", b"", lfence)], None),
        ("repeated-expansion", '''
unsafe {
    alternative!("lfence", "", groups::Second,);
    alternative!("nop", "lfence", groups::Second);
}
''', [("lfence", "", lfence, b""), ("nop", "lfence", nop, lfence)], None),
        ("flags-modified", 'unsafe { alternative!("stc", "clc", groups::Second); }',
         [("stc", "clc", b"\xf9", b"\xf8")], None),
        ("untyped-group", 'unsafe { alternative!("", "lfence", u32); }', [], "E0277"),
        ("branch-group", 'unsafe { alternative!("", "lfence", groups::Branch); }', [], "E0271"),
        ("missing-unsafe", 'alternative!("", "lfence", groups::Second);', [], "E0133"),
    ]
    for optimization in (0, 3):
        for name, body, sites, diagnostic in cases:
            rust_source = directory / "check.rs"
            source = generate_harness(
                "First: Sequence, Second: Sequence, Branch: Branch,",
                f'''
mod consumer {{
    use super::{{alternative_macros::alternative, registry::groups}};
    #[unsafe(no_mangle)]
    pub extern "C" fn test_alternative() {{ {body} }}
}}
pub(super) fn run() {{}}
''',
            )
            rust_source.write_text("#![no_std]\n" + source)
            result = subprocess.run(
                ["rustc", "--edition=2024", "--crate-type=lib", "--cfg=ktest",
                 "--target=x86_64-unknown-none", "--emit=obj,llvm-ir",
                 "-C", f"opt-level={optimization}", str(rust_source),
                 "--out-dir", str(directory)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            label = f"rust interface, opt-level={optimization}, {name}"
            if diagnostic is not None:
                if result.returncode == 0 or diagnostic not in result.stderr:
                    raise RuntimeError(f"{label}: unexpected result\n{result.stderr}")
            else:
                if result.returncode != 0:
                    raise RuntimeError(f"{label}: {result.stderr}")
                check_linked_slots(directory, sites)
                # The interface promises a compiler memory barrier and permits
                # flag changes even when its original instructions are empty.
                assembly = [
                    line for line in (directory / "check.ll").read_text().splitlines()
                    if "asm sideeffect" in line and ".altinstructions" in line
                ]
                assert len(assembly) == len(sites), label
                assert all("~{memory}" in line and "~{flags}" in line for line in assembly), label
            print(f"PASS: {label}")


def check_builder_types(directory):
    entries = """
Sequence: Sequence,
Branch: Branch,
TailCall: TailCall(extern "C" fn(u64) -> u64),
OtherTailCall: TailCall(extern "C" fn(u64) -> u64),
Call: Call,
"""
    cases = [
        ("accepted-contracts", """
let mut boot = AlternativePatchBuilder::<AlternativeBoot>::new(table);
boot.replace_sequence(table.all::<groups::Sequence>()).unwrap();
boot.set_branch(table.all::<groups::Branch>(), AlternativeBranchState::Disabled, AlternativeBranchState::Enabled).unwrap();
boot.retarget_tail_call(table.all::<groups::TailCall>(), groups::TailCall::target(handler), groups::TailCall::target(handler)).unwrap();
unsafe { boot.commit(); }
let mut runtime = AlternativePatchBuilder::<AlternativeRuntime>::new(table);
runtime.set_call(table.all::<groups::Call>(), AlternativeCallState::Disabled, AlternativeCallState::Disabled).unwrap();
""", None),
        ("runtime-sequence", """
let mut builder = AlternativePatchBuilder::<AlternativeRuntime>::new(table);
builder.replace_sequence(table.all::<groups::Sequence>());
""", "E0599"),
        ("wrong-site-kind", """
let mut builder = AlternativePatchBuilder::<AlternativeBoot>::new(table);
builder.set_branch(table.all::<groups::Sequence>(), AlternativeBranchState::Disabled, AlternativeBranchState::Enabled);
""", "E0271"),
        ("wrong-function-signature", "let _ = groups::TailCall::target(wrong_handler);", "E0308"),
        ("wrong-tail-call-group", """
let mut builder = AlternativePatchBuilder::<AlternativeBoot>::new(table);
builder.retarget_tail_call(table.all::<groups::TailCall>(), groups::OtherTailCall::target(handler), groups::TailCall::target(handler));
""", "E0308"),
        ("ordinary-function-as-trampoline", "let _ = AlternativeCallState::Enabled(handler);", "E0308"),
        ("consumed-builder", """
let mut builder = AlternativePatchBuilder::<AlternativeBoot>::new(table);
unsafe { builder.commit(); }
builder.replace_sequence(table.all::<groups::Sequence>());
""", "E0382"),
        ("runtime-commit", """
let builder = AlternativePatchBuilder::<AlternativeRuntime>::new(table);
unsafe { builder.commit(); }
""", "E0599"),
        ("commit-without-unsafe", """
let builder = AlternativePatchBuilder::<AlternativeBoot>::new(table);
builder.commit();
""", "E0133"),
        ("private-preparation", """
let builder = AlternativePatchBuilder::<AlternativeBoot>::new(table);
let _ = builder.prepare();
""", "E0624"),
    ]
    for name, body, diagnostic in cases:
        source = generate_harness(entries, f"""
use request::*;
use table::AlternativeTable;
extern "C" fn handler(value: u64) -> u64 {{ value }}
extern "C" fn wrong_handler(value: u32) -> u32 {{ value }}
fn exercise(table: &AlternativeTable) {{ {body} }}
pub(super) fn run() {{}}
""", builder=True)
        rust_source = directory / "builder.rs"
        rust_source.write_text(source)
        result = subprocess.run(
            ["rustc", "--edition=2024", "--crate-type=lib", "--emit=metadata",
             str(rust_source), "-o", str(directory / "builder.rmeta")],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        label = f"builder types, {name}"
        if diagnostic is None:
            passed = result.returncode == 0
        else:
            passed = result.returncode != 0 and diagnostic in result.stderr
        if not passed:
            raise RuntimeError(f"{label}: unexpected result\n{result.stderr}")
        print(f"PASS: {label}")


def main():
    nop = b"\x90"
    lfence = b"\x0f\xae\xe8"
    # The local jump must relax from a short jump to a five-byte near jump.
    branch = "jmp 7f; .fill 128,1,0x90; 7:"
    branch_bytes = b"\xe9\x80\x00\x00\x00" + nop * 128
    valid_sites = [
        ("equal", ("add rax, 1", "add rax, 42", b"\x48\x83\xc0\x01", b"\x48\x83\xc0\x2a")),
        ("replacement-longer", ("nop", "lfence", nop, lfence)),
        ("original-longer", ("lfence", "nop", lfence, nop)),
        ("insert", ("", "lfence", b"", lfence)),
        ("remove", ("lfence", "", lfence, b"")),
        ("maximum-original", (".fill 65535,1,0x90", "nop", nop * 65535, nop)),
        ("maximum-replacement", ("nop", ".fill 65535,1,0x90", nop, nop * 65535)),
        ("original-local-branch", (branch, "nop", branch_bytes, nop)),
        ("replacement-local-branch", ("nop", branch, nop, branch_bytes)),
    ]
    cases = [(name, [site], None) for name, site in valid_sites]
    cases.append(("mixed-repeated-expansion", [site for _, site in valid_sites[:5]], None))
    cases.extend([
        ("empty-slot", [("", "", b"", b"")], "invalid .org offset"),
        ("oversized-original", [(".fill 65536,1,0x90", "nop", b"", b"")], "invalid .org offset"),
        ("oversized-replacement", [("nop", ".fill 65536,1,0x90", b"", b"")], "invalid .org offset"),
    ])
    with tempfile.TemporaryDirectory(prefix="ostd-alternatives-") as temporary:
        directory = Path(temporary)
        check_id_registry(directory)
        check_rust_interface(directory)
        check_builder_types(directory)
        for frontend in ("rust", "assembly"):
            for optimization in (0, 3):
                for name, sites, diagnostic in cases:
                    rust_source = directory / "check.rs"
                    rust_source.write_text(generate_test_source(frontend, sites))
                    result = subprocess.run(
                        [
                            "rustc", "--edition=2024", "--crate-type=lib", "--cfg=ktest",
                            "--target=x86_64-unknown-none",
                            "--emit=obj", "-C", f"opt-level={optimization}",
                            str(rust_source), "-o", str(directory / "check.o"),
                        ],
                        cwd=ROOT, capture_output=True, text=True, check=False,
                    )
                    if diagnostic is None:
                        passed = result.returncode == 0
                    else:
                        passed = result.returncode != 0 and diagnostic in result.stderr
                    label = f"{frontend}, opt-level={optimization}, {name}"
                    if not passed:
                        raise RuntimeError(f"{label}: unexpected result\n{result.stderr}")
                    if diagnostic is None:
                        check_linked_slots(directory, sites)
                    print(f"PASS: {label}")


if __name__ == "__main__":
    main()
