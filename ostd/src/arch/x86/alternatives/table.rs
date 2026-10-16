// SPDX-License-Identifier: MPL-2.0

//! Descriptor layout, linker sections, and validation before code is written.

#[cfg(ktest)]
mod test;

use alloc::vec::Vec;
use core::{mem::offset_of, ops::Range};

use super::{
    AlternativesError,
    condition::{AlternativeId, AlternativeIdMap},
};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct AlternativeDescriptor {
    target_offset_bytes: i32,
    replacement_offset_bytes: i32,
    condition_id: u32,
    slot_len_bytes: u16,
    replacement_len_bytes: u16,
}

const _: () = {
    assert!(size_of::<AlternativeDescriptor>() == 16);
    assert!(align_of::<AlternativeDescriptor>() == 4);
    assert!(offset_of!(AlternativeDescriptor, target_offset_bytes) == 0);
    assert!(offset_of!(AlternativeDescriptor, replacement_offset_bytes) == 4);
    assert!(offset_of!(AlternativeDescriptor, condition_id) == 8);
    assert!(offset_of!(AlternativeDescriptor, slot_len_bytes) == 12);
    assert!(offset_of!(AlternativeDescriptor, replacement_len_bytes) == 14);
};

pub(super) struct AlternativePatch {
    target_range: Range<usize>,
    replacement_range: Range<usize>,
    is_enabled: bool,
}

/// Validates the linked descriptors and looks up their frozen conditions.
///
/// # Safety
///
/// The kernel image, including its linker-owned descriptor table, must be mapped
/// and readable. The descriptor table must remain immutable during validation.
/// The returned ranges do not borrow instruction bytes.
pub(super) unsafe fn validate_linked_alternatives(
    id_map: &AlternativeIdMap,
) -> Result<Vec<AlternativePatch>, AlternativesError> {
    let table =
        __altinstructions_start as *const () as usize..__altinstructions_end as *const () as usize;
    let text = __text_start as *const () as usize..__text_end as *const () as usize;
    let replacements = __altinstr_replacement_start as *const () as usize
        ..__altinstr_replacement_end as *const () as usize;
    let count = descriptor_count(&table)?;

    // SAFETY: The linker owns this aligned, immutable table. Its length and
    // layout have been checked, and AlternativeDescriptor accepts all field bit patterns.
    let descriptors =
        unsafe { core::slice::from_raw_parts(table.start as *const AlternativeDescriptor, count) };
    validate_descriptors(descriptors, &text, &replacements, id_map)
}

fn descriptor_count(table: &Range<usize>) -> Result<usize, AlternativesError> {
    let len = table
        .end
        .checked_sub(table.start)
        .ok_or(AlternativesError::InvalidTable)?;
    if !table
        .start
        .is_multiple_of(align_of::<AlternativeDescriptor>())
        || !len.is_multiple_of(size_of::<AlternativeDescriptor>())
        || len > isize::MAX as usize
    {
        return Err(AlternativesError::InvalidTable);
    }
    Ok(len / size_of::<AlternativeDescriptor>())
}

/// Validates metadata and selects patches without accessing instruction bytes.
fn validate_descriptors(
    descriptors: &[AlternativeDescriptor],
    text: &Range<usize>,
    replacements: &Range<usize>,
    id_map: &AlternativeIdMap,
) -> Result<Vec<AlternativePatch>, AlternativesError> {
    let mut patches = Vec::with_capacity(descriptors.len());
    for descriptor in descriptors {
        let mut patch = descriptor.resolve(descriptor as *const _ as usize, text, replacements)?;
        let condition_id = AlternativeId::from_raw(descriptor.condition_id)
            .ok_or(AlternativesError::UnknownCondition)?;
        patch.is_enabled = id_map.is_enabled(condition_id);
        patches.push(patch);
    }

    patches.sort_unstable_by_key(|patch| patch.target_range.start);
    if patches
        .windows(2)
        .any(|pair| pair[0].target_range.end > pair[1].target_range.start)
    {
        return Err(AlternativesError::OverlappingSlots);
    }
    Ok(patches)
}

impl AlternativePatch {
    pub(super) fn target_range(&self) -> &Range<usize> {
        &self.target_range
    }

    pub(super) fn replacement_range(&self) -> &Range<usize> {
        &self.replacement_range
    }

    pub(super) fn is_enabled(&self) -> bool {
        self.is_enabled
    }
}

impl AlternativeDescriptor {
    fn resolve(
        &self,
        address: usize,
        text: &Range<usize>,
        replacements: &Range<usize>,
    ) -> Result<AlternativePatch, AlternativesError> {
        if self.slot_len_bytes == 0 || self.replacement_len_bytes > self.slot_len_bytes {
            return Err(AlternativesError::InvalidLength);
        }
        let target_range = relative_range(address, self.target_offset_bytes, self.slot_len_bytes)?;
        let replacement_field = address
            .checked_add(offset_of!(Self, replacement_offset_bytes))
            .ok_or(AlternativesError::AddressOverflow)?;
        let replacement_range = relative_range(
            replacement_field,
            self.replacement_offset_bytes,
            self.replacement_len_bytes,
        )?;
        if target_range.start < text.start || target_range.end > text.end {
            return Err(AlternativesError::OutsideText);
        }
        if replacement_range.start < replacements.start || replacement_range.end > replacements.end
        {
            return Err(AlternativesError::OutsideReplacement);
        }
        Ok(AlternativePatch {
            target_range,
            replacement_range,
            is_enabled: false,
        })
    }
}

fn relative_range(base: usize, offset: i32, len: u16) -> Result<Range<usize>, AlternativesError> {
    let start = base
        .checked_add_signed(offset as isize)
        .ok_or(AlternativesError::AddressOverflow)?;
    let end = start
        .checked_add(usize::from(len))
        .ok_or(AlternativesError::AddressOverflow)?;
    Ok(start..end)
}

// Defined by the x86-64 OSDK linker script. They are address markers, not
// callable functions. The replacement section is outside the target text range.
unsafe extern "C" {
    fn __text_start();
    fn __text_end();
    fn __altinstructions_start();
    fn __altinstructions_end();
    fn __altinstr_replacement_start();
    fn __altinstr_replacement_end();
}
