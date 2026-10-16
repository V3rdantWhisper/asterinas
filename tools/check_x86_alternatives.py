#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0

"""Check alternatives assembly and condition IDs with the pinned Rust toolchain."""

import json
from pathlib import Path
import struct
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
MACROS = ROOT / "ostd/src/arch/x86/alternatives"


def generate_id_registry_source(entries, body):
    return f"""
#[path = {json.dumps(str(MACROS / 'alternative_macros.rs'))}]
mod alternative_macros;
mod condition {{
    use super::alternative_macros::define_alternative_ids;
    define_alternative_ids! {{
        pub(super) enum AlternativeId {{ {entries} }}
    }}
}}
use condition::AlternativeId;
{body}
"""


def check_id_registry(directory):
    # Cross a bitmap word boundary and put a conditional ID in the middle,
    # so cfg changes must affect both enum numbering and the generated list.
    entries = [f"Condition{index}," for index in range(65)]
    entries.insert(10, "#[cfg(ktest)] TestCondition,")
    body = """
fn main() {
    assert_eq!(AlternativeId::COUNT, if cfg!(ktest) { 66 } else { 65 });
    for (index, &id) in AlternativeId::ALL.iter().enumerate() {
        assert_eq!(id.as_raw() as usize, index);
        assert_eq!(AlternativeId::from_raw(index as u32), Some(id));
    }
    assert_eq!(AlternativeId::from_raw(AlternativeId::COUNT as u32), None);
    assert_eq!(AlternativeId::from_raw(u32::MAX), None);
}
"""
    rust_source = directory / "registry.rs"
    rust_source.write_text(generate_id_registry_source("\n".join(entries), body))
    for configuration in ([], ["--cfg=ktest"]):
        executable = directory / "registry"
        result = subprocess.run(
            ["rustc", "--edition=2024", *configuration, str(rust_source),
             "-o", str(executable)],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"condition registry: {result.stderr}")
        subprocess.run([str(executable)], check=True)
        print(f"PASS: condition IDs, ktest={bool(configuration)}, word boundary and cfg")

    cases = [
        ("duplicate-name", "First, First,", "fn main() {}", "E0428"),
        ("explicit-number", "First = 7,", "fn main() {}", "no rules expected"),
        ("untyped-id", "First,", """
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
            raise RuntimeError(f"condition IDs, {name}: unexpected result\n{result.stderr}")
        print(f"PASS: condition IDs, {name} rejected")


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
        alt_condition_id = const 1,
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
    assert len(table) == len(sites) * 16
    assert replacements == b"".join(new for _, _, _, new in sites)
    previous_end = None
    for index, (_, _, old, new) in enumerate(sites):
        target_offset, replacement_offset, condition, slot_len, replacement_len = (
            struct.unpack_from("<iiIHH", table, index * 16)
        )
        assert condition == 1
        assert slot_len == max(len(old), len(new))
        assert replacement_len == len(new)
        target = table_address + index * 16 + target_offset
        if previous_end is not None:
            assert target == previous_end
        previous_end = target + slot_len
        text_offset = target - text_address
        assert 0 <= text_offset <= len(text) - slot_len
        assert text[text_offset:text_offset + slot_len] == old + b"\x90" * (slot_len - len(old))
        if replacement_len:
            source = table_address + index * 16 + 4 + replacement_offset - replacement_address
            assert 0 <= source <= len(replacements) - replacement_len
            assert replacements[source:source + replacement_len] == new


def check_rust_interface(directory):
    nop = b"\x90"
    lfence = b"\x0f\xae\xe8"
    cases = [
        ("typed-constant", """
const CONDITION: AlternativeId = AlternativeId::Second;
unsafe { alternative!("", "lfence", CONDITION); }
""", [("", "lfence", b"", lfence)], None),
        ("repeated-expansion", """
unsafe {
    alternative!("lfence", "", AlternativeId::Second,);
    alternative!("nop", "lfence", AlternativeId::Second);
}
""", [("lfence", "", lfence, b""), ("nop", "lfence", nop, lfence)], None),
        ("flags-modified", """
unsafe { alternative!("stc", "clc", AlternativeId::Second); }
""", [("stc", "clc", b"\xf9", b"\xf8")], None),
        ("untyped-id", """
unsafe { alternative!("", "lfence", 1u32); }
""", [], "E0308"),
        ("foreign-id", """
struct OtherId;
impl OtherId { const fn as_raw(self) -> u32 { 1 } }
unsafe { alternative!("", "lfence", OtherId); }
""", [], "E0308"),
        ("runtime-id", """
let condition = AlternativeId::Second;
unsafe { alternative!("", "lfence", condition); }
""", [], "E0435"),
        ("missing-unsafe", """
alternative!("", "lfence", AlternativeId::Second);
""", [], "E0133"),
    ]
    for optimization in (0, 3):
        for name, body, sites, diagnostic in cases:
            rust_source = directory / "check.rs"
            # Match OSTD's module paths and import only the public-facing macro
            # in a sibling consumer, so its helper names cannot resolve by accident.
            rust_source.write_text(f"""
#![no_std]
mod arch {{
    mod alternatives {{
        #[path = {json.dumps(str(MACROS / 'alternative_macros.rs'))}]
        mod alternative_macros;
        mod condition {{
            use super::alternative_macros::define_alternative_ids;
            define_alternative_ids! {{
                pub(super) enum AlternativeId {{ First, Second, }}
            }}
        }}
        mod consumer {{
            use super::{{alternative_macros::alternative, condition::AlternativeId}};
            #[unsafe(no_mangle)]
            pub extern "C" fn test_alternative() {{ {body} }}
        }}
    }}
}}
""")
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
