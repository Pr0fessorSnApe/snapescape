; SNAPESCAPE x86_64 fast checksum — performance-critical path
; uint16_t snapescape_checksum_asm(const void *data, size_t len);

section .text
global snapescape_checksum_asm

snapescape_checksum_asm:
    xor eax, eax
    xor edx, edx
.test:
    cmp rsi, 0
    je .done
    movzx ecx, byte [rdi]
    add eax, ecx
    inc rdi
    dec rsi
    jmp .short
.done:
    mov ax, 0xFFFF
    not eax
    and eax, 0xFFFF
    ret
