/* SPDX-License-Identifier: MPL-2.0 */

/* Include in the same global_asm! as its callers, then .purgem the macro.
 * See alternative_macros.rs for the instruction and caller-side safety requirements.
 * Both frontends emit the 16-byte AlternativeDescriptor ABI defined in table.rs.
 * Pass condition_id from AlternativeId::as_raw() through a global_asm! operand.
 */
.macro OSTD_ALTERNATIVE old:req, new:req, condition_id:req
.Lostd_alt_old_\@:
    \old
.Lostd_alt_old_end_\@:
    .set .Lostd_alt_old_len_bytes_\@, .Lostd_alt_old_end_\@ - .Lostd_alt_old_\@
    .set .Lostd_alt_new_len_bytes_\@, .Lostd_alt_new_end_\@ - .Lostd_alt_new_\@
    .set .Lostd_alt_growth_bytes_\@, .Lostd_alt_new_len_bytes_\@ - .Lostd_alt_old_len_bytes_\@
    /* Comparisons yield -1 for true; pad only when the replacement is longer. */
    .skip -(.Lostd_alt_growth_bytes_\@ > 0) * .Lostd_alt_growth_bytes_\@, 0x90
.Lostd_alt_slot_end_\@:
    .set .Lostd_alt_slot_len_bytes_\@, .Lostd_alt_slot_end_\@ - .Lostd_alt_old_\@

    .pushsection .altinstructions,"a",@progbits

    .balign 4
    .long .Lostd_alt_old_\@ - .
    .long .Lostd_alt_new_\@ - .
    .long \condition_id
    .short .Lostd_alt_slot_len_bytes_\@
    .short .Lostd_alt_new_len_bytes_\@
    .popsection

    .pushsection .altinstr_replacement,"ax",@progbits
    .code64

.Lostd_alt_new_\@:
    \new
.Lostd_alt_new_end_\@:
    /* Check during layout: a true comparison moves .org backwards and fails. */
    .org . + ((.Lostd_alt_slot_len_bytes_\@ == 0) | (.Lostd_alt_slot_len_bytes_\@ > 65535))
    .popsection
.endm
