/* SPDX-License-Identifier: MPL-2.0 */

.text
.code64

.global ostd_alt_test_asm_add
.type ostd_alt_test_asm_add, @function
ostd_alt_test_asm_add:
    mov rax, rdi
    OSTD_ALTERNATIVE "add rax, 1", "add rax, 42", {replace_add_condition_id}
    ret
.size ostd_alt_test_asm_add, .-ostd_alt_test_asm_add

.global ostd_alt_test_asm_add_twice
.type ostd_alt_test_asm_add_twice, @function
ostd_alt_test_asm_add_twice:
    mov rax, rdi
    OSTD_ALTERNATIVE "add rax, 1", "add rax, 42; nop; nop", {replace_add_condition_id}
    OSTD_ALTERNATIVE "add rax, 1; nop", "add rax, 42", {replace_add_condition_id}
    ret
.size ostd_alt_test_asm_add_twice, .-ostd_alt_test_asm_add_twice
