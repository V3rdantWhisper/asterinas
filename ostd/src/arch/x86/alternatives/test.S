/* SPDX-License-Identifier: MPL-2.0 */

.text
.code64

.global ostd_alt_test_asm_add
.type ostd_alt_test_asm_add, @function
ostd_alt_test_asm_add:
    mov rax, rdi
    OSTD_ALTERNATIVE "add rax, 1", "add rax, 42", {replace_add_group_id}
    ret
.size ostd_alt_test_asm_add, .-ostd_alt_test_asm_add

.global ostd_alt_test_asm_add_twice
.type ostd_alt_test_asm_add_twice, @function
ostd_alt_test_asm_add_twice:
    mov rax, rdi
    OSTD_ALTERNATIVE "add rax, 1", "add rax, 42; nop; nop", {replace_add_group_id}
    OSTD_ALTERNATIVE "add rax, 1; nop", "add rax, 42", {replace_add_group_id}
    ret
.size ostd_alt_test_asm_add_twice, .-ostd_alt_test_asm_add_twice

.global ostd_alt_test_branch
.type ostd_alt_test_branch, @function
ostd_alt_test_branch:
    OSTD_ALTERNATIVE_BRANCH .Lostd_alt_test_log, {branch_group_id}
    mov eax, 1
    ret
.Lostd_alt_test_log:
    mov eax, 42
    ret
.size ostd_alt_test_branch, .-ostd_alt_test_branch

.global ostd_alt_test_branch_unselected
.type ostd_alt_test_branch_unselected, @function
ostd_alt_test_branch_unselected:
    OSTD_ALTERNATIVE_BRANCH .Lostd_alt_test_log_unselected, {branch_group_id}
    mov eax, 1
    ret
.Lostd_alt_test_log_unselected:
    mov eax, 42
    ret
.size ostd_alt_test_branch_unselected, .-ostd_alt_test_branch_unselected

.global ostd_alt_test_tail_call
.type ostd_alt_test_tail_call, @function
ostd_alt_test_tail_call:
    OSTD_ALTERNATIVE_TAIL_CALL ostd_alt_test_old_handler, {tail_call_group_id}
.size ostd_alt_test_tail_call, .-ostd_alt_test_tail_call

.global ostd_alt_test_old_handler
.type ostd_alt_test_old_handler, @function
ostd_alt_test_old_handler:
    lea rax, [rdi + 1]
    ret
.size ostd_alt_test_old_handler, .-ostd_alt_test_old_handler

.global ostd_alt_test_new_handler
.type ostd_alt_test_new_handler, @function
ostd_alt_test_new_handler:
    lea rax, [rdi + 42]
    ret
.size ostd_alt_test_new_handler, .-ostd_alt_test_new_handler

.global ostd_alt_test_traced
.type ostd_alt_test_traced, @function
ostd_alt_test_traced:
    OSTD_ALTERNATIVE_CALL {trace_group_id}
    lea rax, [rdi + 1]
    ret
.size ostd_alt_test_traced, .-ostd_alt_test_traced

.global ostd_alt_test_trace_trampoline
.type ostd_alt_test_trace_trampoline, @function
ostd_alt_test_trace_trampoline:
    pushfq
    lock inc qword ptr [rip + ostd_alt_test_trace_count]
    popfq
    ret
.size ostd_alt_test_trace_trampoline, .-ostd_alt_test_trace_trampoline
