// SPDX-License-Identifier: MPL-2.0

//! Condition IDs and incremental selection of boot-time alternatives.
//!
//! IDs name conditions, not instruction encodings or patch sites.
//! Policy owners update individual conditions before the BSP freezes the bitmap.
//! Conditions start disabled except `AlternativeId::Always`.
//! Updates and freezing share a lock; the published bitmap is immutable.
//! Selecting a condition does not itself patch any instructions.

#[cfg(ktest)]
mod test;

use spin::Once;

use super::alternative_macros::define_alternative_ids;
use crate::sync::{LocalIrqDisabled, SpinLock};

static ALTERNATIVE_ID_MAP: Once<AlternativeIdMap> = Once::new();
static ALTERNATIVE_ID_MAP_STATE: SpinLock<AlternativeIdMapState, LocalIrqDisabled> =
    SpinLock::new(AlternativeIdMapState::new());

/// Enables one condition before the boot policy is frozen.
///
/// Repeated enabling is harmless.
/// A policy owner may change its choice until freezing; the last successful update wins.
/// Other conditions are unchanged, and no instructions are patched by this call.
/// Call from boot initialization, never from NMI or exception handlers.
///
/// # Errors
///
/// Returns [`AlternativeUpdateError::Frozen`] once the pending map has been frozen.
#[cfg_attr(not(ktest), expect(dead_code))]
pub(in crate::arch) fn enable_condition(id: AlternativeId) -> Result<(), AlternativeUpdateError> {
    ALTERNATIVE_ID_MAP_STATE.lock().enable(id)
}

/// Disables one condition before the boot policy is frozen.
///
/// Repeated disabling is harmless.
/// Other conditions are unchanged, and `Always` cannot be disabled.
/// This does not revert an applied patch: updates after freezing are rejected.
/// Call from boot initialization, never from NMI or exception handlers.
///
/// # Errors
///
/// Returns [`AlternativeUpdateError::Frozen`] after freezing.
/// Before freezing, disabling `Always` returns [`AlternativeUpdateError::AlwaysEnabled`].
#[cfg_attr(not(ktest), expect(dead_code))]
pub(in crate::arch) fn disable_condition(id: AlternativeId) -> Result<(), AlternativeUpdateError> {
    ALTERNATIVE_ID_MAP_STATE.lock().disable(id)
}

/// Freezes and publishes all conditions before validating any patch.
///
/// Publication records the selection, not completion of instruction patching.
/// The pending map is removed under the same lock used by updates, so no update
/// can succeed after the snapshot has been taken.
pub(super) fn freeze_on_bsp() -> &'static AlternativeIdMap {
    ALTERNATIVE_ID_MAP.call_once(|| {
        ALTERNATIVE_ID_MAP_STATE
            .lock()
            .freeze()
            .expect("alternatives conditions have already been frozen")
    })
}

define_alternative_ids! {
    pub(in crate::arch) enum AlternativeId {
        // Always select the replacement. Every site still needs a safety audit.
        Always,
        #[cfg(ktest)] TestDisabled,
        #[cfg(ktest)] TestEnabled,
    }
}

const BITS_PER_WORD: usize = u64::BITS as usize;

/// An unsuccessful update to a boot-time alternative condition.
#[derive(Debug, Eq, PartialEq)]
pub(in crate::arch) enum AlternativeUpdateError {
    /// Condition selection has already been frozen for patching.
    Frozen,
    /// The unconditional replacement condition cannot be disabled.
    AlwaysEnabled,
}

/// Condition selection while boot policies are being applied.
struct AlternativeIdMapState {
    // Taking the map closes the update interface before publishing the snapshot.
    pending: Option<AlternativeIdMap>,
}

impl AlternativeIdMapState {
    const fn new() -> Self {
        Self {
            pending: Some(AlternativeIdMap::new()),
        }
    }

    fn enable(&mut self, id: AlternativeId) -> Result<(), AlternativeUpdateError> {
        let (word, mask) = self.condition_bit(id)?;
        *word |= mask;
        Ok(())
    }

    fn disable(&mut self, id: AlternativeId) -> Result<(), AlternativeUpdateError> {
        let (word, mask) = self.condition_bit(id)?;
        if id == AlternativeId::Always {
            return Err(AlternativeUpdateError::AlwaysEnabled);
        }
        *word &= !mask;
        Ok(())
    }

    fn condition_bit(
        &mut self,
        id: AlternativeId,
    ) -> Result<(&mut u64, u64), AlternativeUpdateError> {
        let map = self
            .pending
            .as_mut()
            .ok_or(AlternativeUpdateError::Frozen)?;
        let index = id.as_raw() as usize;
        Ok((
            &mut map.words[index / BITS_PER_WORD],
            1u64 << (index % BITS_PER_WORD),
        ))
    }

    fn freeze(&mut self) -> Result<AlternativeIdMap, AlternativeUpdateError> {
        self.pending.take().ok_or(AlternativeUpdateError::Frozen)
    }
}

/// Condition bits that become immutable when published for this kernel boot.
pub(super) struct AlternativeIdMap {
    words: [u64; AlternativeId::COUNT.div_ceil(BITS_PER_WORD)],
}

impl AlternativeIdMap {
    const fn new() -> Self {
        let mut map = Self {
            words: [0; AlternativeId::COUNT.div_ceil(BITS_PER_WORD)],
        };
        let index = AlternativeId::Always.as_raw() as usize;
        map.words[index / BITS_PER_WORD] |= 1u64 << (index % BITS_PER_WORD);
        map
    }

    pub(super) fn is_enabled(&self, id: AlternativeId) -> bool {
        let index = id.as_raw() as usize;
        self.words[index / BITS_PER_WORD] & (1u64 << (index % BITS_PER_WORD)) != 0
    }
}

#[cfg(ktest)]
pub(super) fn boot_id_map() -> &'static AlternativeIdMap {
    ALTERNATIVE_ID_MAP.get().unwrap()
}
