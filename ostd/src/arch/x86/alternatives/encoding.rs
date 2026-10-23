// SPDX-License-Identifier: MPL-2.0

//! Encodings shared by branch, tail-call, and call requests.

use super::AlternativesError;

pub(super) const CONTROL_SLOT_LEN: usize = 5;
// A single five-byte instruction, not five independently executable NOPs.
pub(super) const CONTROL_NOP: [u8; CONTROL_SLOT_LEN] = [0x0f, 0x1f, 0x44, 0x00, 0x00];

pub(super) enum AlternativeControlTransfer {
    Jump,
    Call,
}

/// Encodes a relative control transfer at its final execution address.
pub(super) fn encode_control_transfer(
    transfer: AlternativeControlTransfer,
    address: usize,
    destination: usize,
) -> Result<[u8; CONTROL_SLOT_LEN], AlternativesError> {
    let next = address
        .checked_add(CONTROL_SLOT_LEN)
        .ok_or(AlternativesError::AddressOverflow)?;
    let displacement = i32::try_from(destination as i128 - next as i128)
        .map_err(|_| AlternativesError::DisplacementOutOfRange)?;
    let mut bytes = CONTROL_NOP;
    bytes[0] = match transfer {
        AlternativeControlTransfer::Jump => 0xe9,
        AlternativeControlTransfer::Call => 0xe8,
    };
    bytes[1..].copy_from_slice(&displacement.to_le_bytes());
    Ok(bytes)
}
