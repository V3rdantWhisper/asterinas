/* SPDX-License-Identifier: MPL-2.0 */

.text
.code64

/* Exercise a slot that straddles a cache-line boundary. */
.balign 64
.skip 62, 0x90
.global ostd_alt_runtime_branch
.type ostd_alt_runtime_branch, @function
ostd_alt_runtime_branch:
    OSTD_ALTERNATIVE_BRANCH .Lostd_alt_runtime_enabled, {branch_group_id}
    mov eax, 1
    ret
.Lostd_alt_runtime_enabled:
    mov eax, 42
    ret
.size ostd_alt_runtime_branch, .-ostd_alt_runtime_branch

.global ostd_alt_runtime_tail_call
.type ostd_alt_runtime_tail_call, @function
ostd_alt_runtime_tail_call:
    OSTD_ALTERNATIVE_TAIL_CALL ostd_alt_runtime_old, {tail_call_group_id}
.size ostd_alt_runtime_tail_call, .-ostd_alt_runtime_tail_call

.global ostd_alt_runtime_old
.type ostd_alt_runtime_old, @function
ostd_alt_runtime_old:
    lea rax, [rdi + 1]
    ret
.size ostd_alt_runtime_old, .-ostd_alt_runtime_old

.global ostd_alt_runtime_new
.type ostd_alt_runtime_new, @function
ostd_alt_runtime_new:
    lea rax, [rdi + 42]
    ret
.size ostd_alt_runtime_new, .-ostd_alt_runtime_new

.global ostd_alt_runtime_traced
.type ostd_alt_runtime_traced, @function
ostd_alt_runtime_traced:
    OSTD_ALTERNATIVE_CALL {trace_group_id}
    lea rax, [rdi + 1]
    ret
.size ostd_alt_runtime_traced, .-ostd_alt_runtime_traced

.global ostd_alt_runtime_trace_trampoline
.type ostd_alt_runtime_trace_trampoline, @function
ostd_alt_runtime_trace_trampoline:
    pushfq
    lock inc qword ptr [rip + ostd_alt_runtime_trace_count]
    popfq
    ret
.size ostd_alt_runtime_trace_trampoline, .-ostd_alt_runtime_trace_trampoline

/* Check flags, a caller-saved register and the return value across tracing.
 * RSI=0 tests entry with RSP mod 16=8, RSI=8 tests RSP mod 16=0. */
.global ostd_alt_runtime_check_trace
.type ostd_alt_runtime_check_trace, @function
ostd_alt_runtime_check_trace:
    push rbx
    mov rbx, rsi
    sub rsp, rbx
    mov r10, 0x12345678
    stc
    call ostd_alt_runtime_traced
    jnc .Lostd_alt_runtime_bad_trace
    cmp r10, 0x12345678
    jne .Lostd_alt_runtime_bad_trace
    lea r10, [rdi + 1]
    cmp rax, r10
    jne .Lostd_alt_runtime_bad_trace
    mov eax, 1
    jmp .Lostd_alt_runtime_trace_done
.Lostd_alt_runtime_bad_trace:
    xor eax, eax
.Lostd_alt_runtime_trace_done:
    add rsp, rbx
    pop rbx
    ret
.size ostd_alt_runtime_check_trace, .-ostd_alt_runtime_check_trace
