// SPDX-License-Identifier: MPL-2.0

use super::*;
use crate::prelude::*;

#[ktest]
fn boot_conditions_include_individual_updates() {
    let id_map = boot_id_map();
    assert!(id_map.is_enabled(AlternativeId::Always));
    assert!(!id_map.is_enabled(AlternativeId::TestDisabled));
    assert!(id_map.is_enabled(AlternativeId::TestEnabled));
}

#[ktest]
fn independent_updates_preserve_other_conditions() {
    let mut state = AlternativeIdMapState::new();
    let initial = state.pending.as_ref().unwrap();
    assert!(initial.is_enabled(AlternativeId::Always));
    assert!(!initial.is_enabled(AlternativeId::TestDisabled));
    assert!(!initial.is_enabled(AlternativeId::TestEnabled));

    state.enable(AlternativeId::TestEnabled).unwrap();
    state.enable(AlternativeId::TestEnabled).unwrap();
    state.enable(AlternativeId::TestDisabled).unwrap();
    state.disable(AlternativeId::TestEnabled).unwrap();
    state.disable(AlternativeId::TestEnabled).unwrap();

    let frozen = state.freeze().unwrap();
    assert!(frozen.is_enabled(AlternativeId::Always));
    assert!(frozen.is_enabled(AlternativeId::TestDisabled));
    assert!(!frozen.is_enabled(AlternativeId::TestEnabled));
    assert_eq!(
        state.enable(AlternativeId::TestEnabled),
        Err(AlternativeUpdateError::Frozen)
    );
    assert_eq!(
        state.disable(AlternativeId::TestDisabled),
        Err(AlternativeUpdateError::Frozen)
    );
    assert_eq!(state.freeze().err(), Some(AlternativeUpdateError::Frozen));
    assert!(frozen.is_enabled(AlternativeId::TestDisabled));
    assert!(!frozen.is_enabled(AlternativeId::TestEnabled));
}

#[ktest]
fn always_condition_cannot_be_disabled() {
    let mut state = AlternativeIdMapState::new();
    assert_eq!(
        state.disable(AlternativeId::Always),
        Err(AlternativeUpdateError::AlwaysEnabled)
    );
    state.enable(AlternativeId::Always).unwrap();
    assert!(state.freeze().unwrap().is_enabled(AlternativeId::Always));
}

#[ktest]
fn raw_condition_ids_are_checked() {
    for (index, &id) in AlternativeId::ALL.iter().enumerate() {
        assert_eq!(id.as_raw() as usize, index);
        assert_eq!(AlternativeId::from_raw(id.as_raw()), Some(id));
    }
    // Reject unused bits in the last word as well as out-of-bitmap IDs.
    assert_eq!(AlternativeId::from_raw(AlternativeId::COUNT as u32), None);
    assert_eq!(AlternativeId::from_raw(u32::MAX), None);
}
