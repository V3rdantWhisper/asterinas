// SPDX-License-Identifier: MPL-2.0

use super::*;
use crate::prelude::*;

#[ktest]
fn descriptors_decode_into_typed_sites() {
    let mut descriptor = AlternativeDescriptor {
        target_offset_bytes: -0x1000,
        payload_offset_bytes: 0x1000 - 4,
        group_id: AlternativeId::TestSequence.as_raw(),
        slot_len_bytes: 5,
        replacement_len_bytes: 3,
        kind: AlternativeKindTag::Sequence as u32,
    };
    let site = descriptor.resolve(0x8000).unwrap();
    assert_eq!(site.id, AlternativeId::TestSequence);
    assert_eq!(site.target, 0x7000..0x7005);
    assert!(
        matches!(site.payload, AlternativeSitePayload::Sequence(range) if range == (0x9000..0x9003))
    );

    descriptor.group_id = AlternativeId::TestBranch.as_raw();
    descriptor.kind = AlternativeKindTag::Branch as u32;
    descriptor.replacement_len_bytes = 0;
    let site = descriptor.resolve(0x8000).unwrap();
    assert!(matches!(
        site.payload,
        AlternativeSitePayload::Branch(0x9000)
    ));

    descriptor.group_id = AlternativeId::TestTailCall.as_raw();
    descriptor.kind = AlternativeKindTag::TailCall as u32;
    assert!(matches!(
        descriptor.resolve(0x8000).unwrap().payload,
        AlternativeSitePayload::TailCall
    ));

    descriptor.group_id = AlternativeId::TestTrace.as_raw();
    descriptor.kind = AlternativeKindTag::Call as u32;
    descriptor.payload_offset_bytes = 0;
    assert!(matches!(
        descriptor.resolve(0x8000).unwrap().payload,
        AlternativeSitePayload::Call
    ));
}

#[ktest]
fn decoding_preserves_checked_integer_conversions() {
    let mut descriptor = AlternativeDescriptor {
        target_offset_bytes: 0,
        payload_offset_bytes: 0,
        group_id: u32::MAX,
        slot_len_bytes: 5,
        replacement_len_bytes: 0,
        kind: AlternativeKindTag::Call as u32,
    };
    assert_eq!(
        descriptor.resolve(0x8000).err(),
        Some(AlternativesError::UnknownGroup)
    );
    descriptor.group_id = AlternativeId::TestTrace.as_raw();
    descriptor.kind = u32::MAX;
    assert_eq!(
        descriptor.resolve(0x8000).err(),
        Some(AlternativesError::InvalidKind)
    );
    for (base, offset, len) in [(0, -1, 1), (usize::MAX, 1, 1), (usize::MAX, 0, 1)] {
        assert_eq!(
            relative_range(base, offset, len),
            Err(AlternativesError::AddressOverflow)
        );
    }
    assert_eq!(relative_range(0x8000, -0x7000, 3), Ok(0x1000..0x1003));
}
