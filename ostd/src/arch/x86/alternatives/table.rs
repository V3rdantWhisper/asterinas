// SPDX-License-Identifier: MPL-2.0

//! The common descriptor table and typed selections of its immutable sites.
//!
//! Every site, including branch/tail-call/call sites, is recorded in
//! `.altinstructions`. Selection does not read or borrow executable bytes.
//! OSDK validates the final ELF before packaging; this module only decodes it.

#[cfg(ktest)]
mod test;

use alloc::vec::Vec;
use core::{marker::PhantomData, mem::offset_of, ops::Range, ptr};

use super::{
    AlternativesError,
    registry::{AlternativeGroup, AlternativeId, AlternativeKindTag},
};

/// An immutable catalog of validated, address-sorted sites in the linked image.
pub(in crate::arch) struct AlternativeTable {
    sites: Vec<AlternativeSiteRecord>,
    text: Range<usize>,
}

impl AlternativeTable {
    /// Decodes the sites of a build-validated linked image.
    ///
    /// # Safety
    ///
    /// This exact image must have passed OSDK's final ELF alternatives check.
    /// Its descriptor layout, group/kind mapping, lengths, section boundaries,
    /// and non-overlapping target ranges must retain those validated properties.
    /// Loading must preserve relative addresses and their representability.
    /// The linker-owned descriptor and replacement sections must be mapped,
    /// readable, permanently resident, and immutable. Linker symbols must still
    /// describe these sections accurately, including an aligned, non-null table.
    pub(in crate::arch) unsafe fn from_linked_image() -> Result<Self, AlternativesError> {
        let table = __altinstructions_start as *const () as usize
            ..__altinstructions_end as *const () as usize;
        let text = __text_start as *const () as usize..__text_end as *const () as usize;
        let len = table
            .end
            .checked_sub(table.start)
            .ok_or(AlternativesError::AddressOverflow)?;
        let count = len / size_of::<AlternativeDescriptor>();
        // SAFETY: The final ELF check establishes alignment, size, and section
        // bounds; the caller preserves them in mapped, immutable storage. The
        // raw record accepts every bit pattern.
        let descriptors = unsafe {
            core::slice::from_raw_parts(table.start as *const AlternativeDescriptor, count)
        };
        Self::from_descriptors(descriptors, text)
    }

    /// Selects every site in a registered group.
    #[cfg_attr(not(ktest), expect(dead_code))]
    pub(in crate::arch) fn all<G: AlternativeGroup>(&self) -> AlternativeSelection<'_, G> {
        AlternativeSelection {
            table: self,
            indices: self.sites::<G>().map(|site| site.index).collect(),
            group: PhantomData,
        }
    }

    /// Iterates the group's sites in instruction-address order.
    #[cfg_attr(not(ktest), expect(dead_code))]
    pub(in crate::arch) fn sites<G: AlternativeGroup>(
        &self,
    ) -> impl Iterator<Item = AlternativeSite<'_, G>> {
        self.sites.iter().enumerate().filter_map(|(index, site)| {
            (site.id == G::ID).then_some(AlternativeSite {
                table: self,
                index,
                group: PhantomData,
            })
        })
    }

    /// Selects individual sites, rejecting handles from another catalog.
    #[cfg_attr(not(ktest), expect(dead_code))]
    pub(in crate::arch) fn select<'a, G: AlternativeGroup>(
        &'a self,
        sites: impl IntoIterator<Item = AlternativeSite<'a, G>>,
    ) -> Result<AlternativeSelection<'a, G>, AlternativesError> {
        let mut indices = Vec::new();
        for site in sites {
            if !ptr::eq(self, site.table) {
                return Err(AlternativesError::ForeignTable);
            }
            indices.push(site.index);
        }
        Ok(AlternativeSelection {
            table: self,
            indices,
            group: PhantomData,
        })
    }

    pub(super) fn site(&self, index: usize) -> &AlternativeSiteRecord {
        &self.sites[index]
    }

    pub(super) fn contains_text_address(&self, address: usize) -> bool {
        self.text.contains(&address)
    }

    fn from_descriptors(
        descriptors: &[AlternativeDescriptor],
        text: Range<usize>,
    ) -> Result<Self, AlternativesError> {
        let mut sites = Vec::with_capacity(descriptors.len());
        for descriptor in descriptors {
            sites.push(descriptor.resolve(descriptor as *const _ as usize)?);
        }
        sites.sort_unstable_by_key(|site| site.target.start);
        Ok(Self { sites, text })
    }
}

/// A site belonging to one registered group and one immutable catalog.
pub(in crate::arch) struct AlternativeSite<'a, G: AlternativeGroup> {
    table: &'a AlternativeTable,
    index: usize,
    group: PhantomData<G>,
}

impl<G: AlternativeGroup> AlternativeSite<'_, G> {
    /// Returns the instruction address for an owner's symbol/filter lookup.
    #[cfg_attr(not(ktest), expect(dead_code))]
    pub(in crate::arch) fn address(&self) -> usize {
        self.table.site(self.index).target.start
    }
}

/// A typed subset of one group's sites; constructing it never changes code.
pub(in crate::arch) struct AlternativeSelection<'a, G: AlternativeGroup> {
    table: &'a AlternativeTable,
    indices: Vec<usize>,
    group: PhantomData<G>,
}

impl<G: AlternativeGroup> AlternativeSelection<'_, G> {
    pub(super) fn into_indices(
        self,
        table: &AlternativeTable,
    ) -> Result<Vec<usize>, AlternativesError> {
        if !ptr::eq(self.table, table) {
            return Err(AlternativesError::ForeignTable);
        }
        if self.indices.is_empty() {
            return Err(AlternativesError::EmptySelection);
        }
        Ok(self.indices)
    }
}

/// A 20-byte, four-byte-aligned record emitted by every alternatives frontend.
///
/// Offsets are relative to their own fields. For sequences, payload points into
/// `.altinstr_replacement`. For branches/tail calls, it points to the fixed branch
/// destination/initial tail-call target in `.text`. Call slots reserve it as zero.
/// OSDK checks the kind against the registry emitted by the group's declaration.
#[repr(C)]
#[derive(Clone, Copy)]
struct AlternativeDescriptor {
    target_offset_bytes: i32,
    payload_offset_bytes: i32,
    group_id: u32,
    slot_len_bytes: u16,
    replacement_len_bytes: u16,
    kind: u32,
}

const _: () = {
    assert!(size_of::<AlternativeDescriptor>() == 20);
    assert!(align_of::<AlternativeDescriptor>() == 4);
    assert!(offset_of!(AlternativeDescriptor, target_offset_bytes) == 0);
    assert!(offset_of!(AlternativeDescriptor, payload_offset_bytes) == 4);
    assert!(offset_of!(AlternativeDescriptor, group_id) == 8);
    assert!(offset_of!(AlternativeDescriptor, slot_len_bytes) == 12);
    assert!(offset_of!(AlternativeDescriptor, replacement_len_bytes) == 14);
    assert!(offset_of!(AlternativeDescriptor, kind) == 16);
};

pub(super) struct AlternativeSiteRecord {
    pub(super) id: AlternativeId,
    pub(super) target: Range<usize>,
    pub(super) payload: AlternativeSitePayload,
}

pub(super) enum AlternativeSitePayload {
    Sequence(Range<usize>),
    Branch(usize),
    TailCall,
    Call,
}

impl AlternativeDescriptor {
    /// Decodes IDs and field-relative addresses without revalidating ELF structure.
    fn resolve(&self, address: usize) -> Result<AlternativeSiteRecord, AlternativesError> {
        let id = AlternativeId::from_raw(self.group_id).ok_or(AlternativesError::UnknownGroup)?;
        let kind = AlternativeKindTag::from_raw(self.kind).ok_or(AlternativesError::InvalidKind)?;
        let target = relative_range(address, self.target_offset_bytes, self.slot_len_bytes)?;
        let payload_field = address
            .checked_add(offset_of!(Self, payload_offset_bytes))
            .ok_or(AlternativesError::AddressOverflow)?;
        let payload = match kind {
            AlternativeKindTag::Sequence => AlternativeSitePayload::Sequence(relative_range(
                payload_field,
                self.payload_offset_bytes,
                self.replacement_len_bytes,
            )?),
            AlternativeKindTag::Branch => AlternativeSitePayload::Branch(
                relative_range(payload_field, self.payload_offset_bytes, 1)?.start,
            ),
            AlternativeKindTag::TailCall => AlternativeSitePayload::TailCall,
            AlternativeKindTag::Call => AlternativeSitePayload::Call,
        };
        Ok(AlternativeSiteRecord {
            id,
            target,
            payload,
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

unsafe extern "C" {
    fn __altinstructions_start();
    fn __altinstructions_end();
    fn __text_start();
    fn __text_end();
}
