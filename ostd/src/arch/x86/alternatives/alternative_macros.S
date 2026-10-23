/* SPDX-License-Identifier: MPL-2.0 */

/* Include in the same global_asm! as its callers, then .purgem all five macros.
 * See alternative_macros.rs for the instruction and caller-side safety requirements.
 * Both frontends emit the 20-byte AlternativeDescriptor ABI defined in table.rs.
 * Pass group_id from AlternativeId::as_raw() through a global_asm! operand.
 */
/* Kind tags match AlternativeKindTag in registry.rs. An empty payload is zero. */
.macro OSTD_ALTERNATIVE_DESCRIPTOR target:req, payload, group_id:req, slot_len:req, replacement_len:req, kind:req
    .pushsection .altinstructions,"a",@progbits

    .balign 4
    .long \target - .
    .ifb \payload
    .long 0
    .else
    .long \payload - .
    .endif
    .long \group_id
    .short \slot_len, \replacement_len
    .long \kind
    .popsection
.endm

.macro OSTD_ALTERNATIVE old:req, new:req, group_id:req
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

    OSTD_ALTERNATIVE_DESCRIPTOR .Lostd_alt_old_\@, .Lostd_alt_new_\@, \group_id, .Lostd_alt_slot_len_bytes_\@, .Lostd_alt_new_len_bytes_\@, 0

    .pushsection .altinstr_replacement,"ax",@progbits
    .code64

.Lostd_alt_new_\@:
    \new
.Lostd_alt_new_end_\@:
    /* Check during layout: a true comparison moves .org backwards and fails. */
    .org . + ((.Lostd_alt_slot_len_bytes_\@ == 0) | (.Lostd_alt_slot_len_bytes_\@ > 65535))
    .popsection
.endm

/* A disabled branch. The destination must be in the linked text section. */
.macro OSTD_ALTERNATIVE_BRANCH destination:req, group_id:req
.Lostd_alt_branch_\@:
    .byte 0x0f, 0x1f, 0x44, 0x00, 0x00
    OSTD_ALTERNATIVE_DESCRIPTOR .Lostd_alt_branch_\@, \destination, \group_id, 5, 0, 1
.endm

/* A tail-call slot. Force rel32 rather than allowing short-jump relaxation. */
.macro OSTD_ALTERNATIVE_TAIL_CALL destination:req, group_id:req
.Lostd_alt_tail_call_\@:
    .byte 0xe9
    .long \destination - . - 4
    OSTD_ALTERNATIVE_DESCRIPTOR .Lostd_alt_tail_call_\@, \destination, \group_id, 5, 0, 2
.endm

/* A disabled call slot; enabling it selects a trampoline that preserves the site's state. */
.macro OSTD_ALTERNATIVE_CALL group_id:req
.Lostd_alt_call_\@:
    .byte 0x0f, 0x1f, 0x44, 0x00, 0x00
    OSTD_ALTERNATIVE_DESCRIPTOR .Lostd_alt_call_\@, , \group_id, 5, 0, 3
.endm
