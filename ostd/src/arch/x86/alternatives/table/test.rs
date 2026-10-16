// SPDX-License-Identifier: MPL-2.0

use super::{super::condition, *};
use crate::prelude::*;

const LFENCE_BYTES: &[u8] = &[0x0f, 0xae, 0xe8];
const ADD_ONE_BYTES: &[u8] = &[0x48, 0x83, 0xc0, 0x01];
const ADD_FORTY_TWO_BYTES: &[u8] = &[0x48, 0x83, 0xc0, 0x2a];
const PADDED_ADD_FORTY_TWO_BYTES: &[u8] = &[0x48, 0x83, 0xc0, 0x2a, 0x90, 0x90];

#[ktest]
fn linked_slots_match_selected_instructions() {
    let table =
        __altinstructions_start as *const () as usize..__altinstructions_end as *const () as usize;
    // SAFETY: The linker table is immutable and its layout is validated.
    let descriptors = unsafe {
        core::slice::from_raw_parts(
            table.start as *const AlternativeDescriptor,
            descriptor_count(&table).unwrap(),
        )
    };
    let text = __text_start as *const () as usize..__text_end as *const () as usize;
    let replacements = __altinstr_replacement_start as *const () as usize
        ..__altinstr_replacement_end as *const () as usize;
    assert!(descriptors.len() >= 10);
    let id_map = condition::boot_id_map();
    let mut add_sites = 0;
    let mut fence_sites = 0;
    let mut removal_sites = 0;
    for descriptor in descriptors {
        let patch = descriptor
            .resolve(descriptor as *const _ as usize, &text, &replacements)
            .unwrap();
        let id = AlternativeId::from_raw(descriptor.condition_id).unwrap();
        // SAFETY: All ranges have been checked, and boot-time mutation is over.
        let (slot, replacement) = unsafe {
            (
                core::slice::from_raw_parts(
                    patch.target_range.start as *const u8,
                    patch.target_range.len(),
                ),
                core::slice::from_raw_parts(
                    patch.replacement_range.start as *const u8,
                    patch.replacement_range.len(),
                ),
            )
        };
        let expected = if id_map.is_enabled(id) {
            // Different byte sequences share Always; expectations stay in tests.
            if id == AlternativeId::Always {
                match replacement {
                    ADD_FORTY_TWO_BYTES | PADDED_ADD_FORTY_TWO_BYTES => add_sites += 1,
                    LFENCE_BYTES => fence_sites += 1,
                    [] => removal_sites += 1,
                    _ => {}
                }
            }
            replacement
        } else if id == AlternativeId::TestDisabled {
            assert_eq!(replacement, ADD_FORTY_TWO_BYTES);
            ADD_ONE_BYTES
        } else {
            continue;
        };
        assert!(slot.starts_with(expected));
        assert!(
            slot[expected.len()..]
                .iter()
                .all(|byte| *byte == super::super::NOP_BYTE)
        );
    }
    assert!(add_sites >= 6);
    assert!(fence_sites >= 1);
    assert!(removal_sites >= 1);
}

#[ktest]
fn descriptor_offsets_and_bounds() {
    let mut descriptor = AlternativeDescriptor {
        target_offset_bytes: -0x7000,
        replacement_offset_bytes: 0x1ffc,
        condition_id: AlternativeId::Always.as_raw(),
        slot_len_bytes: 3,
        replacement_len_bytes: 3,
    };
    let patch = descriptor
        .resolve(0x8000, &(0x1000..0x1003), &(0xa000..0xa003))
        .unwrap();
    assert_eq!(patch.target_range, 0x1000..0x1003);
    assert_eq!(patch.replacement_range, 0xa000..0xa003);
    assert_eq!(
        descriptor
            .resolve(0x8000, &(0x1000..0x1002), &(0xa000..0xa003))
            .err(),
        Some(AlternativesError::OutsideText)
    );
    assert_eq!(
        descriptor
            .resolve(0x8000, &(0x1000..0x1003), &(0xa000..0xa002))
            .err(),
        Some(AlternativesError::OutsideReplacement)
    );
    descriptor.replacement_len_bytes = 4;
    assert_eq!(
        descriptor
            .resolve(0x8000, &(0..usize::MAX), &(0..usize::MAX))
            .err(),
        Some(AlternativesError::InvalidLength)
    );
    descriptor.slot_len_bytes = 0;
    assert_eq!(
        descriptor
            .resolve(0x8000, &(0..usize::MAX), &(0..usize::MAX))
            .err(),
        Some(AlternativesError::InvalidLength)
    );
    assert_eq!(
        relative_range(0, -1, 1),
        Err(AlternativesError::AddressOverflow)
    );
    assert_eq!(
        relative_range(usize::MAX, 1, 1),
        Err(AlternativesError::AddressOverflow)
    );
    assert_eq!(
        relative_range(usize::MAX, 0, 1),
        Err(AlternativesError::AddressOverflow)
    );
}

#[ktest]
fn invalid_descriptor_tables() {
    assert_eq!(descriptor_count(&(0x1000..0x1000)), Ok(0));
    assert_eq!(descriptor_count(&(0x1000..0x1020)), Ok(2));
    assert_eq!(
        descriptor_count(&(0x1001..0x1011)),
        Err(AlternativesError::InvalidTable)
    );
    assert_eq!(
        descriptor_count(&(0x1000..0x1011)),
        Err(AlternativesError::InvalidTable)
    );
    let reversed = Range {
        start: 0x1020,
        end: 0x1000,
    };
    assert_eq!(
        descriptor_count(&reversed),
        Err(AlternativesError::InvalidTable)
    );
}

// Keeping all buffers in one allocation makes their distances fit in i32,
// regardless of where the kernel test's stack is mapped.
#[repr(C)]
struct AlternativeTableFixture {
    descriptors: [AlternativeDescriptor; 2],
    text: [u8; 16],
    replacements: [u8; 3],
}

impl AlternativeTableFixture {
    fn new() -> Self {
        Self {
            descriptors: [AlternativeDescriptor {
                target_offset_bytes: 0,
                replacement_offset_bytes: 0,
                condition_id: AlternativeId::Always.as_raw(),
                slot_len_bytes: 8,
                replacement_len_bytes: 3,
            }; 2],
            text: [super::super::NOP_BYTE; 16],
            replacements: [0x0f, 0xae, 0xe8],
        }
    }

    fn update_relative_offsets(&mut self) {
        let text = self.text.as_ptr() as usize;
        let replacement = self.replacements.as_ptr() as usize;
        for (index, descriptor) in self.descriptors.iter_mut().enumerate() {
            let address = descriptor as *const _ as usize;
            descriptor.target_offset_bytes = (text as isize + (index * 8) as isize
                - address as isize)
                .try_into()
                .unwrap();
            let replacement_field =
                address + offset_of!(AlternativeDescriptor, replacement_offset_bytes);
            descriptor.replacement_offset_bytes = (replacement as isize
                - replacement_field as isize)
                .try_into()
                .unwrap();
        }
    }

    fn validate(&self) -> Result<Vec<AlternativePatch>, AlternativesError> {
        let text = self.text.as_ptr() as usize;
        let replacements = self.replacements.as_ptr() as usize;
        validate_descriptors(
            &self.descriptors,
            &(text..text + self.text.len()),
            &(replacements..replacements + self.replacements.len()),
            condition::boot_id_map(),
        )
    }
}

#[ktest]
fn validation_rejects_invalid_sites_without_writing() {
    let mut fixture = AlternativeTableFixture::new();
    fixture.update_relative_offsets();
    assert_eq!(fixture.validate().unwrap().len(), 2);
    fixture.descriptors[1].condition_id = u32::MAX;
    assert_eq!(
        fixture.validate().err(),
        Some(AlternativesError::UnknownCondition)
    );
    assert_eq!(fixture.text, [super::super::NOP_BYTE; 16]);
    fixture.descriptors[1].condition_id = AlternativeId::COUNT as u32;
    assert_eq!(
        fixture.validate().err(),
        Some(AlternativesError::UnknownCondition)
    );
    fixture.descriptors[1].condition_id = AlternativeId::Always.as_raw();
    fixture.descriptors[1].target_offset_bytes -= 8;
    assert_eq!(
        fixture.validate().err(),
        Some(AlternativesError::OverlappingSlots)
    );
    fixture.update_relative_offsets();
    fixture.descriptors[1].slot_len_bytes = 9;
    assert_eq!(
        fixture.validate().err(),
        Some(AlternativesError::OutsideText)
    );
    fixture.descriptors[1].slot_len_bytes = 8;
    fixture.descriptors[1].replacement_len_bytes = 4;
    assert_eq!(
        fixture.validate().err(),
        Some(AlternativesError::OutsideReplacement)
    );
    assert_eq!(fixture.text, [super::super::NOP_BYTE; 16]);
}

#[ktest]
fn disabled_sites_are_still_validated() {
    let mut fixture = AlternativeTableFixture::new();
    fixture.update_relative_offsets();
    for descriptor in &mut fixture.descriptors {
        descriptor.condition_id = AlternativeId::TestDisabled.as_raw();
    }
    assert!(fixture.validate().unwrap().iter().all(|p| !p.is_enabled));
    fixture.descriptors[0].replacement_len_bytes = 9;
    assert_eq!(
        fixture.validate().err(),
        Some(AlternativesError::InvalidLength)
    );
}

#[ktest]
fn one_condition_selects_different_instruction_sequences() {
    let mut fixture = AlternativeTableFixture::new();
    fixture.update_relative_offsets();
    fixture.text[8..11].copy_from_slice(LFENCE_BYTES);
    fixture.descriptors[1].replacement_len_bytes = 0;
    let patches = fixture.validate().unwrap();
    assert_eq!(patches.len(), 2);
    assert!(patches.iter().all(|patch| patch.is_enabled));
    assert_eq!(patches[0].replacement_range.len(), LFENCE_BYTES.len());
    assert!(patches[1].replacement_range.is_empty());
    // Validation selects both insertion and removal without changing either slot.
    assert_eq!(&fixture.text[..8], &[super::super::NOP_BYTE; 8]);
    assert_eq!(&fixture.text[8..11], LFENCE_BYTES);
}
