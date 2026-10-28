// SPDX-License-Identifier: MPL-2.0

use std::process::Command;

use super::*;

// Exercise real ELF parsing, symbol boundaries, LOAD mappings and resolved
// offsets, rather than handing the checker pre-parsed synthetic records.
const ASSEMBLY: &str = r#"
.text
.code64

sequence: .byte 0x90, 0x90, 0x90
branch: .byte 0x0f, 0x1f, 0x44, 0, 0
tail_call: .byte 0xe9
      .long destination - . - 4
call: .byte 0x0f, 0x1f, 0x44, 0, 0
destination: ret
.section .altinstr_replacement,"ax",@progbits
.code64

replacement: lfence
.section .altinstructions,"a",@progbits

.balign 4
.long sequence - ., replacement - ., 0
.short 3, 3
.long 0
.long branch - ., destination - ., 1
.short 5, 0
.long 1
.long tail_call - ., destination - ., 2
.short 5, 0
.long 2
.long call - ., 0, 3
.short 5, 0
.long 3
.section .altgroups,"a",@progbits

.balign 4
.long 1, 20, 4, 0, 1, 2, 3
"#;

const LINKER_SCRIPT: &str = r#"
PHDRS { code PT_LOAD FLAGS(5); rodata PT_LOAD FLAGS(4); }
SECTIONS {
    . = 0xffffffff88000000;
    .text : AT(ADDR(.text) - 0xffffffff80000000) {
        __text_start = .;
        __alternatives_protected_start = .;
        *(.text.alternatives_protected)
        __alternatives_protected_end = .;
        *(.text) __text_end = .;
    } : code
    .altinstr_replacement : AT(ADDR(.altinstr_replacement) - 0xffffffff80000000) {
        __altinstr_replacement_start = .;
        *(.altinstr_replacement)
        __altinstr_replacement_end = .;
    } : code
    . = ALIGN(4096);
    .altinstructions : AT(ADDR(.altinstructions) - 0xffffffff80000000) {
        __altinstructions_start = .;
        *(.altinstructions)
        __altinstructions_end = .;
    } : rodata
    .altgroups : AT(ADDR(.altgroups) - 0xffffffff80000000) { *(.altgroups) } : rodata
}
"#;

fn linked_fixture() -> Vec<u8> {
    linked_fixture_with(ASSEMBLY, LINKER_SCRIPT)
}

fn linked_fixture_with(assembly: &str, linker_script: &str) -> Vec<u8> {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("sites.S"), assembly).unwrap();
    fs::write(directory.path().join("sites.ld"), linker_script).unwrap();
    for (command, args) in [
        ("as", vec!["--64", "sites.S", "-o", "sites.o"]),
        ("ld", vec!["-T", "sites.ld", "sites.o", "-o", "sites.elf"]),
    ] {
        let output = Command::new(command)
            .args(args)
            .current_dir(directory.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    fs::read(directory.path().join("sites.elf")).unwrap()
}

fn section_offset(bytes: &[u8], name: &str) -> usize {
    find_section(&ElfFile::new(bytes).unwrap(), name)
        .unwrap()
        .offset() as usize
}

fn section_header_offset(elf: &ElfFile<'_>, name: &str) -> usize {
    let index = (1..elf.header.pt2.sh_count())
        .find(|index| elf.section_header(*index).unwrap().get_name(elf).unwrap() == name)
        .unwrap();
    elf.header.pt2.sh_offset() as usize
        + usize::from(index) * usize::from(elf.header.pt2.sh_entry_size())
}

fn set_symbol_value(bytes: &mut [u8], name: &str, value: u64) {
    let elf = ElfFile::new(bytes).unwrap();
    let symbols = find_section(&elf, ".symtab").unwrap();
    let strings = find_section(&elf, ".strtab").unwrap();
    let strings = strings.raw_data(&elf);
    let index = symbols
        .raw_data(&elf)
        .as_chunks::<24>()
        .0
        .iter()
        .position(|symbol| string_at(strings, u32_at(symbol, 0)).unwrap() == name)
        .unwrap();
    let offset = symbols.offset() as usize + index * 24 + 8;
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn clear_descriptors(bytes: &mut [u8]) {
    let elf = ElfFile::new(bytes).unwrap();
    let start = find_section(&elf, ".altinstructions").unwrap().address();
    let size_field = section_header_offset(&elf, ".altinstructions") + 32;
    bytes[size_field..size_field + 8].copy_from_slice(&0u64.to_le_bytes());
    set_symbol_value(bytes, "__altinstructions_end", start);
}

fn validate(bytes: &[u8]) -> Result<usize, String> {
    let image = AlternativeElf::parse(bytes)?;
    let protected = image.validate_symbols()?;
    image.validate(&protected)
}

fn assert_invalid(bytes: &[u8], message: &str) {
    let err = validate(bytes).unwrap_err();
    assert!(err.contains(message), "expected {message:?}, got {err:?}");
}

#[test]
fn all_four_site_contracts_are_validated_in_a_linked_elf() {
    assert_eq!(validate(&linked_fixture()).unwrap(), 4);
}

#[test]
fn malformed_descriptors_are_rejected_even_without_a_patch_request() {
    let original = linked_fixture();
    let table = section_offset(&original, ".altinstructions");
    for (offset, value, message) in [
        (8, u32::MAX.to_le_bytes().to_vec(), "unknown group"),
        (16, 1u32.to_le_bytes().to_vec(), "mismatched kind"),
        (
            16,
            u32::MAX.to_le_bytes().to_vec(),
            "unknown alternative kind",
        ),
        (12, 0u16.to_le_bytes().to_vec(), "invalid slot"),
        (14, 4u16.to_le_bytes().to_vec(), "invalid slot"),
        (0, 0i32.to_le_bytes().to_vec(), "target outside"),
        (4, 0i32.to_le_bytes().to_vec(), "replacement outside"),
        (32, 4u16.to_le_bytes().to_vec(), "five-byte slot"),
        (34, 1u16.to_le_bytes().to_vec(), "no replacement"),
        (24, 0i32.to_le_bytes().to_vec(), "destination outside"),
        (64, 1u32.to_le_bytes().to_vec(), "zero payload"),
    ] {
        let mut bytes = original.clone();
        bytes[table + offset..table + offset + value.len()].copy_from_slice(&value);
        assert_invalid(&bytes, message);
    }
    let mut overlap = original.clone();
    // Turn the last record into a second sequence targeting the first slot.
    let first = original[table..table + 20].to_vec();
    overlap[table + 60..table + 80].copy_from_slice(&first);
    for field in [0, 4] {
        let offset = (u32_at(&first, field) as i32 - 60).to_le_bytes();
        overlap[table + 60 + field..table + 64 + field].copy_from_slice(&offset);
    }
    assert_invalid(&overlap, "overlapping");

    let mut inside = original.clone();
    let branch_offset = u32_at(&original, table + 20) as i32;
    inside[table + 24..table + 28].copy_from_slice(&(branch_offset - 4).to_le_bytes());
    assert_invalid(&inside, "inside its own slot");
}

#[test]
fn registry_version_count_and_kinds_are_checked() {
    let original = linked_fixture();
    let registry = section_offset(&original, ".altgroups");
    for (offset, value, message) in [
        (0, 2u32, "unsupported"),
        (4, 16, "unsupported"),
        (8, 3, "unsupported"),
        (12, 4, "unknown alternative kind"),
        (12, 3, "mismatched kind"),
    ] {
        let mut bytes = original.clone();
        bytes[registry + offset..registry + offset + 4].copy_from_slice(&value.to_le_bytes());
        assert_invalid(&bytes, message);
    }
}

#[test]
fn initial_control_instructions_are_checked() {
    let original = linked_fixture();
    let text = section_offset(&original, ".text");
    for offset in [3, 8, 13] {
        let mut bytes = original.clone();
        bytes[text + offset] = 0xcc;
        assert_invalid(
            &bytes,
            if offset == 13 {
                "NOP5"
            } else {
                "initial control"
            },
        );
    }
    let mut wrong_tail_call = original.clone();
    wrong_tail_call[text + 9] ^= 1;
    assert_invalid(&wrong_tail_call, "initial control");
}

#[test]
fn table_layout_and_load_mapping_are_checked() {
    let original = linked_fixture();
    let elf = ElfFile::new(&original).unwrap();
    let header_offset = section_header_offset(&elf, ".altinstructions");
    for (field, value, message) in [
        (32, 79u64, "multiple of 20"),
        (16, u64_at(&original, header_offset + 16) + 1, "aligned"),
        (8, 3, "read-only"),
        (24, u64::MAX, "overflow"),
    ] {
        let mut bytes = original.clone();
        bytes[header_offset + field..header_offset + field + 8]
            .copy_from_slice(&value.to_le_bytes());
        if field == 32 {
            let end = find_section(&elf, ".altinstructions").unwrap().address() + value;
            set_symbol_value(&mut bytes, "__altinstructions_end", end);
        }
        assert_invalid(&bytes, message);
    }
    let mut unmapped = original.clone();
    // Second LOAD segment holds the descriptors and the group registry.
    let flags = elf.header.pt2.ph_offset() as usize + 56 + 4;
    unmapped[flags..flags + 4].copy_from_slice(&6u32.to_le_bytes());
    assert_invalid(&unmapped, "invalid load mapping");

    let mut truncated = original.clone();
    truncated.truncate(original.len() - 64);
    assert_invalid(&truncated, "truncated ELF");
}

#[test]
fn linker_boundaries_must_match_the_validated_sections() {
    let mut bytes = linked_fixture();
    let elf = ElfFile::new(&bytes).unwrap();
    let symbols = find_section(&elf, ".symtab").unwrap();
    let strings = find_section(&elf, ".strtab").unwrap();
    let strings = file_bytes(&bytes, strings.offset(), strings.size()).unwrap();
    let table = file_bytes(&bytes, symbols.offset(), symbols.size()).unwrap();
    let index = table
        .as_chunks::<24>()
        .0
        .iter()
        .position(|symbol| string_at(strings, u32_at(symbol, 0)).unwrap() == "__text_end")
        .unwrap();
    let offset = symbols.offset() as usize + index * 24 + 8;
    bytes[offset] ^= 1;
    assert_invalid(&bytes, "__text_end does not match");
}

#[test]
fn stripping_and_qemu_headers_preserve_the_checked_image() {
    let directory = tempfile::tempdir().unwrap();
    let linked = directory.path().join("linked.elf");
    let boot = directory.path().join("boot.elf");
    fs::write(&linked, linked_fixture()).unwrap();
    let checked = ValidatedAlternatives::read(&linked).unwrap();
    assert!(
        Command::new("strip")
            .arg("-o")
            .arg(&boot)
            .arg(&linked)
            .status()
            .unwrap()
            .success()
    );
    checked.verify_preserved(&boot).unwrap();
    let mut bytes = fs::read(&boot).unwrap();
    bytes[18..20].copy_from_slice(&3u16.to_le_bytes());
    fs::write(&boot, &bytes).unwrap();
    checked.verify_preserved(&boot).unwrap();
    let offset = section_offset(&bytes, ".text");
    bytes[offset] ^= 1;
    fs::write(&boot, &bytes).unwrap();
    assert!(
        checked
            .verify_preserved(&boot)
            .unwrap_err()
            .contains(".text changed")
    );
}

#[test]
fn relative_addresses_reject_overflow_and_preserve_negative_offsets() {
    for (base, offset, len) in [(0, -1, 1), (u64::MAX, 1, 1), (u64::MAX, 0, 1)] {
        assert!(relative_range(base, offset, len).is_err());
    }
    assert_eq!(relative_range(0x8000, -0x7000, 3).unwrap(), 0x1000..0x1003);
}

#[test]
fn physical_loading_must_match_the_kernel_virtual_mapping() {
    let original = linked_fixture();
    let elf = ElfFile::new(&original).unwrap();
    let headers = elf.header.pt2.ph_offset() as usize;
    let rodata_pa = headers + 56 + 24;
    let mut wrong_backing = original.clone();
    wrong_backing[rodata_pa..rodata_pa + 8].copy_from_slice(&0x0900_0000u64.to_le_bytes());
    assert_invalid(&wrong_backing, "incorrect physical backing");

    let mut overlapping = original.clone();
    let text_pa = u64_at(&original, headers + 24);
    overlapping[rodata_pa..rodata_pa + 8].copy_from_slice(&text_pa.to_le_bytes());
    assert_invalid(&overlapping, "overlapping physical LOAD segments");
}

#[test]
fn decoy_descriptors_cannot_hide_the_bytes_loaded_at_runtime() {
    let mut bytes = linked_fixture();
    let elf = ElfFile::new(&bytes).unwrap();
    let table = find_section(&elf, ".altinstructions").unwrap();
    let section_header = section_header_offset(&elf, ".altinstructions");
    let program_headers = elf.header.pt2.ph_offset() as usize;
    let table_offset = table.offset() as usize;
    let table_address = table.address();
    let pristine = table.raw_data(&elf).to_vec();

    // Keep malformed descriptors at their real physical load address, while
    // pointing the ELF section at a pristine copy in a disjoint decoy LOAD.
    bytes[table_offset + 12..table_offset + 14].copy_from_slice(&1u16.to_le_bytes());
    bytes[table_offset + 14..table_offset + 16].copy_from_slice(&u16::MAX.to_le_bytes());
    let decoy_offset = bytes.len().next_multiple_of(4096);
    bytes.resize(decoy_offset, 0);
    bytes.extend_from_slice(&pristine);
    bytes[section_header + 24..section_header + 32]
        .copy_from_slice(&(decoy_offset as u64).to_le_bytes());

    // Insert the decoy before the real rodata LOAD, as a first-match virtual
    // address lookup would otherwise select the genuine segment.
    bytes.copy_within(
        program_headers + 56..program_headers + 112,
        program_headers + 112,
    );
    bytes[56..58].copy_from_slice(&3u16.to_le_bytes());
    let decoy = &mut bytes[program_headers + 56..program_headers + 112];
    decoy[..4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD.
    decoy[4..8].copy_from_slice(&4u32.to_le_bytes()); // Read-only.
    for (field, value) in [
        (8, decoy_offset as u64),
        (16, table_address),
        (24, 0x0900_0000),
        (32, pristine.len() as u64),
        (40, pristine.len() as u64),
        (48, 4096),
    ] {
        decoy[field..field + 8].copy_from_slice(&value.to_le_bytes());
    }
    assert_invalid(&bytes, "overlapping virtual LOAD segments");
}

#[test]
fn protected_text_accepts_boot_sequences_but_rejects_every_runtime_kind() {
    let protected = ".section .text.alternatives_protected,\"ax\",@progbits\n.code64\n\n";
    let boot_only = ASSEMBLY
        .replace("sequence:", &format!("{protected}sequence:"))
        .replace("branch:", ".text\n.code64\n\nbranch:");
    assert_eq!(
        validate(&linked_fixture_with(&boot_only, LINKER_SCRIPT)).unwrap(),
        4
    );
    for (start, end) in [
        ("branch:", "tail_call:"),
        ("tail_call:", "call:"),
        ("call:", "destination:"),
    ] {
        let assembly = ASSEMBLY
            .replace(&format!("\n{start}"), &format!("\n{protected}{start}"))
            .replace(&format!("\n{end}"), &format!("\n.text\n.code64\n\n{end}"));
        assert_invalid(
            &linked_fixture_with(&assembly, LINKER_SCRIPT),
            "runtime slot overlaps protected text",
        );
    }
}

#[test]
fn protected_boundaries_are_required_and_checked_without_any_sites() {
    let mut empty = linked_fixture();
    clear_descriptors(&mut empty);
    assert_eq!(validate(&empty).unwrap(), 0);
    for (replacement, message) in [
        ("", "missing linker symbol __alternatives_protected_end"),
        (
            "__alternatives_protected_end = . - 1;",
            "reversed protected text",
        ),
        (
            "__alternatives_protected_end = . + 0x100000;",
            "protected range outside .text",
        ),
    ] {
        let script = LINKER_SCRIPT.replace("__alternatives_protected_end = .;", replacement);
        let mut bytes = linked_fixture_with(ASSEMBLY, &script);
        clear_descriptors(&mut bytes);
        assert_invalid(&bytes, message);
    }
}

#[test]
fn even_partial_runtime_slot_overlap_with_protected_text_is_rejected() {
    // Put only the last byte of the branch inside the protected range.
    let script = LINKER_SCRIPT
        .replace(
            "__alternatives_protected_start = .;",
            "__alternatives_protected_start = . + 7;",
        )
        .replace(
            "__alternatives_protected_end = .;",
            "__alternatives_protected_end = . + 8;",
        );
    assert_invalid(
        &linked_fixture_with(ASSEMBLY, &script),
        "runtime slot overlaps protected text",
    );
}
