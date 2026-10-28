// SPDX-License-Identifier: MPL-2.0

//! Mandatory validation of x86 alternatives in the linked kernel ELF.
//!
//! This is the structural safety boundary for OSTD's descriptor decoder. It
//! checks every record, including sites that no boot policy selects. It cannot
//! prove instruction semantics, position independence, or calling conventions.

#[cfg(test)]
mod test;

use std::{fs, ops::Range, path::Path};

use xmas_elf::{
    ElfFile, header, program,
    sections::{self, SectionHeader, ShType},
};

const DESCRIPTOR_SIZE: usize = 20;
const CONTROL_NOP: [u8; 5] = [0x0f, 0x1f, 0x44, 0, 0];
// This versioned format is shared with OSTD's alternatives registry macro.
const FORMAT_VERSION: u32 = 1;
// The boot mapping in ostd/src/arch/x86/boot/bsp_boot.S and KERNEL_VMA in
// x86_64.ld.template use this offset between permanent kernel VAs and PAs.
const KERNEL_VIRTUAL_OFFSET: u64 = 0xffff_ffff_8000_0000;

#[derive(Clone, Copy, Eq, PartialEq)]
enum AlternativeKind {
    Sequence,
    Branch,
    TailCall,
    Call,
}

impl AlternativeKind {
    fn from_raw(raw: u32) -> Result<Self, String> {
        match raw {
            0 => Ok(Self::Sequence),
            1 => Ok(Self::Branch),
            2 => Ok(Self::TailCall),
            3 => Ok(Self::Call),
            _ => Err(format!("unknown alternative kind {raw}")),
        }
    }
}

/// The validated sections, retained until boot-image transformations finish.
pub(super) struct ValidatedAlternatives {
    sections: [(Range<u64>, Vec<u8>); 4],
}

impl ValidatedAlternatives {
    /// Validates a final linked ELF, including its linker boundary symbols.
    pub(super) fn read(path: &Path) -> Result<Self, String> {
        let bytes = fs::read(path).map_err(|err| err.to_string())?;
        let image = AlternativeElf::parse(&bytes)?;
        let protected = image.validate_symbols()?;
        let count = image.validate(&protected)?;
        info!("Validated {count} x86 alternatives in {}", path.display());
        Ok(Self {
            sections: image
                .sections()
                .map(|(_, section)| (section.range.clone(), section.data.to_vec())),
        })
    }

    /// Checks that stripping and the QEMU ELF-header adjustment preserve sites.
    ///
    /// Symbols may have been stripped, so their previously checked boundaries
    /// are tied to this artifact by comparing section addresses and contents.
    pub(super) fn verify_preserved(&self, path: &Path) -> Result<(), String> {
        let bytes = fs::read(path).map_err(|err| err.to_string())?;
        let image = AlternativeElf::parse(&bytes)?;
        for ((range, data), (name, section)) in self.sections.iter().zip(image.sections()) {
            if section.range != *range || section.data != data {
                return Err(format!("{name} changed during boot-image preparation"));
            }
        }
        Ok(())
    }
}

struct AlternativeElf<'a> {
    elf: ElfFile<'a>,
    text: AlternativeSection<'a>,
    replacements: AlternativeSection<'a>,
    descriptors: AlternativeSection<'a>,
    groups: AlternativeSection<'a>,
}

struct AlternativeSection<'a> {
    range: Range<u64>,
    data: &'a [u8],
}

impl<'a> AlternativeElf<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, String> {
        // Bound the tables before asking xmas-elf to read borrowed headers.
        // EM_386 is accepted only with ELFCLASS64: OSDK changes this field for
        // QEMU multiboot, without changing the x86-64 image's code or layout.
        let elf = ElfFile::new(bytes)?;
        let header = &elf.header.pt2;
        let elf_header_size = size_of::<header::HeaderPt1>() + size_of::<header::HeaderPt2_<u64>>();
        let program_header_size = size_of::<program::ProgramHeader64>();
        let section_header_size = size_of::<sections::SectionHeader_<u64>>();
        if elf.header.pt1.class() != header::Class::SixtyFour
            || elf.header.pt1.data() != header::Data::LittleEndian
            || elf.header.pt1.version() != header::Version::Current
            || header.type_().as_type() != header::Type::Executable
            || !matches!(
                header.machine().as_machine(),
                header::Machine::X86 | header::Machine::X86_64
            )
            || usize::from(header.header_size()) != elf_header_size
            || usize::from(header.ph_entry_size()) != program_header_size
            || usize::from(header.sh_entry_size()) != section_header_size
            || !(1..sections::SHN_LORESERVE).contains(&header.sh_count())
        {
            return Err("expected a linked little-endian ELF64 x86 kernel".into());
        }
        for (offset, count, size) in [
            (header.ph_offset(), header.ph_count(), program_header_size),
            (header.sh_offset(), header.sh_count(), section_header_size),
        ] {
            if !offset.is_multiple_of(align_of::<u64>() as u64) {
                return Err("unaligned ELF header table".into());
            }
            file_bytes(bytes, offset, u64::from(count) * size as u64)?;
        }
        validate_load_segments(&elf)?;
        let read_section_fn = |name: &str| -> Result<_, String> {
            let header = find_section(&elf, name)?;
            let range = address_range(header.address(), header.size())?;
            if header.get_type()? != ShType::ProgBits || header.flags() & sections::SHF_ALLOC == 0 {
                return Err(format!("{name} must be allocated PROGBITS"));
            }
            if !matches!(name, ".text" | ".altinstr_replacement")
                && (header.flags() & (sections::SHF_WRITE | sections::SHF_EXECINSTR) != 0
                    || !range.start.is_multiple_of(align_of::<u32>() as u64))
            {
                return Err(format!("{name} must be aligned, read-only metadata"));
            }
            let data = file_bytes(bytes, header.offset(), header.size())?;
            validate_mapping(&elf, &header, name)?;
            Ok(AlternativeSection { range, data })
        };
        Ok(Self {
            text: read_section_fn(".text")?,
            replacements: read_section_fn(".altinstr_replacement")?,
            descriptors: read_section_fn(".altinstructions")?,
            groups: read_section_fn(".altgroups")?,
            elf,
        })
    }

    fn sections(&self) -> [(&'static str, &AlternativeSection<'a>); 4] {
        [
            (".text", &self.text),
            (".altinstr_replacement", &self.replacements),
            (".altinstructions", &self.descriptors),
            (".altgroups", &self.groups),
        ]
    }

    fn validate(&self, protected: &Range<u64>) -> Result<usize, String> {
        let Self {
            text,
            replacements,
            descriptors: table,
            groups: registry,
            ..
        } = self;
        let sections = self.sections();
        for (index, (_, left)) in sections.iter().enumerate() {
            for (_, right) in &sections[index + 1..] {
                if !left.range.is_empty()
                    && !right.range.is_empty()
                    && left.range.start < right.range.end
                    && right.range.start < left.range.end
                {
                    return Err("alternatives sections overlap".into());
                }
            }
        }
        let words = registry.data;
        if words.len() < 12
            || !words.len().is_multiple_of(4)
            || u32_at(words, 0) != FORMAT_VERSION
            || u32_at(words, 4) != DESCRIPTOR_SIZE as u32
            || u64::from(u32_at(words, 8)) != ((words.len() - 12) / 4) as u64
        {
            return Err("invalid or unsupported .altgroups format".into());
        }
        let kinds = words[12..]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| AlternativeKind::from_raw(u32_at(word, 0)))
            .collect::<Result<Vec<_>, _>>()?;
        if table.range.start == 0 {
            return Err("null alternatives table address".into());
        }
        if !table.data.len().is_multiple_of(DESCRIPTOR_SIZE) {
            return Err(".altinstructions size is not a multiple of 20".into());
        }
        let mut targets = Vec::new();
        for (index, record) in table
            .data
            .as_chunks::<DESCRIPTOR_SIZE>()
            .0
            .iter()
            .enumerate()
        {
            let address = table.range.start + (index * DESCRIPTOR_SIZE) as u64;
            let target = validate_descriptor(record, address, &kinds, text, replacements)
                .map_err(|err| format!("alternative #{index} at {address:#x}: {err}"))?;
            if AlternativeKind::from_raw(u32_at(record, 16))? != AlternativeKind::Sequence
                && !protected.is_empty()
                && target.start < protected.end
                && protected.start < target.end
            {
                return Err(format!(
                    "alternative #{index} at {address:#x}: runtime slot overlaps protected text"
                ));
            }
            targets.push(target);
        }
        targets.sort_unstable_by_key(|range| range.start);
        if targets.windows(2).any(|pair| pair[0].end > pair[1].start) {
            return Err("overlapping alternative target slots".into());
        }
        Ok(targets.len())
    }

    fn validate_symbols(&self) -> Result<Range<u64>, String> {
        let symbols = find_section(&self.elf, ".symtab")?;
        if symbols.get_type()? != ShType::SymTab
            || symbols.entry_size() != 24
            || !symbols.size().is_multiple_of(24)
        {
            return Err("invalid ELF symbol table".into());
        }
        let strings_index = u16::try_from(symbols.link()).map_err(|err| err.to_string())?;
        if strings_index >= self.elf.header.pt2.sh_count() {
            return Err("invalid symbol string table index".into());
        }
        let strings = self.elf.section_header(strings_index)?;
        let strings = file_bytes(self.elf.input, strings.offset(), strings.size())?;
        let symbols = file_bytes(self.elf.input, symbols.offset(), symbols.size())?;
        let symbol_value_fn = |name: &str| -> Result<u64, String> {
            let mut found = None;
            for symbol in symbols.as_chunks::<24>().0.iter() {
                if string_at(strings, u32_at(symbol, 0))? == name
                    && u16_at(symbol, 6) != 0
                    && found.replace(u64_at(symbol, 8)).is_some()
                {
                    return Err(format!("duplicate linker symbol {name}"));
                }
            }
            found.ok_or_else(|| format!("missing linker symbol {name}"))
        };
        for (section, prefix) in [
            (&self.text, "__text"),
            (&self.replacements, "__altinstr_replacement"),
            (&self.descriptors, "__altinstructions"),
        ] {
            for (suffix, expected) in [("start", section.range.start), ("end", section.range.end)] {
                let name = format!("{prefix}_{suffix}");
                if symbol_value_fn(&name)? != expected {
                    return Err(format!("{name} does not match the section boundary"));
                }
            }
        }
        let protected = symbol_value_fn("__alternatives_protected_start")?
            ..symbol_value_fn("__alternatives_protected_end")?;
        if protected.start > protected.end {
            return Err("reversed protected text boundaries".into());
        }
        require_contains(
            &self.text.range,
            &protected,
            "protected range outside .text",
        )?;
        Ok(protected)
    }
}

fn validate_descriptor(
    record: &[u8],
    address: u64,
    kinds: &[AlternativeKind],
    text: &AlternativeSection<'_>,
    replacements: &AlternativeSection<'_>,
) -> Result<Range<u64>, String> {
    let group = u32_at(record, 8) as usize;
    let kind = AlternativeKind::from_raw(u32_at(record, 16))?;
    if kinds.get(group) != Some(&kind) {
        return Err("unknown group ID or mismatched kind".into());
    }
    let slot_len = u64::from(u16_at(record, 12));
    let replacement_len = u64::from(u16_at(record, 14));
    if slot_len == 0 || replacement_len > slot_len {
        return Err("invalid slot/replacement length".into());
    }
    let target = relative_range(address, u32_at(record, 0) as i32, slot_len)?;
    require_contains(&text.range, &target, "target outside .text")?;
    let payload_offset = u32_at(record, 4) as i32;
    let payload_field = address.checked_add(4).ok_or("payload address overflow")?;
    if kind == AlternativeKind::Sequence {
        let source = relative_range(payload_field, payload_offset, replacement_len)?;
        require_contains(
            &replacements.range,
            &source,
            "replacement outside .altinstr_replacement",
        )?;
        // Even an empty source becomes a Rust slice at runtime.
        if source.start == 0 {
            return Err("null replacement address".into());
        }
        return Ok(target);
    }
    if slot_len != 5 || replacement_len != 0 {
        return Err("control sites require a five-byte slot and no replacement bytes".into());
    }
    let offset = usize::try_from(target.start - text.range.start).map_err(|err| err.to_string())?;
    let original = &text.data[offset..offset + 5];
    if kind == AlternativeKind::Call {
        if payload_offset != 0 || original != CONTROL_NOP {
            return Err("call slot requires zero payload and NOP5".into());
        }
        return Ok(target);
    }
    let destination = relative_range(payload_field, payload_offset, 1)?;
    require_contains(&text.range, &destination, "destination outside .text")?;
    if target.contains(&destination.start) {
        return Err("destination inside its own slot".into());
    }
    let displacement = i32::try_from(i128::from(destination.start) - i128::from(target.end))
        .map_err(|_| "destination outside rel32 range")?;
    let mut jump = [0xe9, 0, 0, 0, 0];
    jump[1..].copy_from_slice(&displacement.to_le_bytes());
    let expected = if kind == AlternativeKind::Branch {
        CONTROL_NOP
    } else {
        jump
    };
    if original != expected {
        return Err("initial control instruction does not match its descriptor".into());
    }
    Ok(target)
}

fn find_section<'a>(elf: &ElfFile<'a>, name: &str) -> Result<SectionHeader<'a>, String> {
    let index = elf.header.pt2.sh_str_index();
    if index >= elf.header.pt2.sh_count() {
        return Err("invalid section name table index".into());
    }
    let strings = elf.section_header(index)?;
    let strings = file_bytes(elf.input, strings.offset(), strings.size())?;
    let mut found = None;
    for index in 1..elf.header.pt2.sh_count() {
        let header = elf.section_header(index)?;
        if string_at(strings, header.name())? == name && found.replace(header).is_some() {
            return Err(format!("duplicate {name} section"));
        }
    }
    found.ok_or_else(|| format!("missing {name} section"))
}

fn validate_mapping(
    elf: &ElfFile<'_>,
    section: &SectionHeader<'_>,
    name: &str,
) -> Result<(), String> {
    // An empty section has no file-backed bytes to load.
    if section.size() == 0 {
        return Ok(());
    }
    let range = address_range(section.address(), section.size())?;
    for index in 0..elf.header.pt2.ph_count() {
        let segment = elf.program_header(index)?;
        if segment.get_type()? != xmas_elf::program::Type::Load {
            continue;
        }
        let mapped = address_range(segment.virtual_addr(), segment.file_size())?;
        if range.start < mapped.start || range.end > mapped.end {
            continue;
        }
        if segment.virtual_addr().checked_sub(segment.physical_addr())
            != Some(KERNEL_VIRTUAL_OFFSET)
        {
            return Err(format!(
                "{name} has incorrect physical backing for the kernel mapping"
            ));
        }
        let file_offset = segment
            .offset()
            .checked_add(range.start - mapped.start)
            .ok_or("segment file offset overflow")?;
        let code = matches!(name, ".text" | ".altinstr_replacement");
        if segment.mem_size() < segment.file_size()
            || file_offset != section.offset()
            || !segment.flags().is_read()
            || segment.flags().is_write()
            || (code
                && (!segment.flags().is_execute()
                    || section.flags() & sections::SHF_EXECINSTR == 0))
        {
            return Err(format!("{name} has an invalid load mapping"));
        }
        return Ok(());
    }
    Err(format!("{name} is not backed by a readable LOAD segment"))
}

fn validate_load_segments(elf: &ElfFile<'_>) -> Result<(), String> {
    let mut physical_ranges = Vec::new();
    let mut virtual_ranges = Vec::new();
    for index in 0..elf.header.pt2.ph_count() {
        let segment = elf.program_header(index)?;
        if segment.get_type()? != program::Type::Load {
            continue;
        }
        if segment.file_size() > segment.mem_size() {
            return Err("LOAD file size exceeds memory size".into());
        }
        file_bytes(elf.input, segment.offset(), segment.file_size())?;
        if segment.mem_size() == 0 {
            continue;
        }
        physical_ranges.push(address_range(segment.physical_addr(), segment.mem_size())?);
        virtual_ranges.push(address_range(segment.virtual_addr(), segment.mem_size())?);
    }
    // A later LOAD's bytes or zero-fill must not overwrite a checked section,
    // nor may a second virtual mapping conceal different physical backing.
    for (name, mut ranges) in [("physical", physical_ranges), ("virtual", virtual_ranges)] {
        ranges.sort_unstable_by_key(|range| range.start);
        if ranges.windows(2).any(|pair| pair[0].end > pair[1].start) {
            return Err(format!("overlapping {name} LOAD segments"));
        }
    }
    Ok(())
}

fn address_range(start: u64, len: u64) -> Result<Range<u64>, String> {
    if len > i64::MAX as u64 {
        return Err("range exceeds the Rust slice size limit".into());
    }
    Ok(start..start.checked_add(len).ok_or("address overflow")?)
}

fn relative_range(base: u64, offset: i32, len: u64) -> Result<Range<u64>, String> {
    address_range(
        base.checked_add_signed(i64::from(offset))
            .ok_or("relative address overflow")?,
        len,
    )
}

fn require_contains(outer: &Range<u64>, inner: &Range<u64>, message: &str) -> Result<(), String> {
    if inner.start < outer.start || inner.end > outer.end {
        return Err(message.into());
    }
    Ok(())
}

fn file_bytes(bytes: &[u8], offset: u64, len: u64) -> Result<&[u8], String> {
    let range = address_range(offset, len)?;
    let start = usize::try_from(range.start).map_err(|err| err.to_string())?;
    let end = usize::try_from(range.end).map_err(|err| err.to_string())?;
    bytes
        .get(start..end)
        .ok_or_else(|| "truncated ELF data".into())
}

fn string_at(bytes: &[u8], offset: u32) -> Result<&str, String> {
    let tail = bytes
        .get(offset as usize..)
        .ok_or("string offset outside table")?;
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or("unterminated ELF string")?;
    std::str::from_utf8(&tail[..end]).map_err(|err| err.to_string())
}

// Callers pass fixed-width records only after bounding their enclosing table.
fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
