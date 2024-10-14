/**
 * Mozilla Public License (MPL) Version 2.0.
 * 
 * Copyright (c) 2024 Tijme Gommers (@tijme).
 * 
 * This source code file is part of Kong Loader. Kong Loader is 
 * licensed under Mozilla Public License (MPL) Version 2.0, and 
 * you are free to use, modify, and distribute this file under 
 * its terms. However, any modified versions of this file must 
 * include this same license and copyright notice.
 */

/**
 * Predefined definitions
 */
#define STATIC_SHELLCODE_NAME "Custom-AccessViolation-1" // Name to be printed
#define STATIC_SHELLCODE_IS_ALREADY_ENCRYPTED 0x0 // May only be negative for debugging purposes with plain static shellcode
#define STATIC_SHELLCODE_HAS_RETURN_VALUE 0x1 // Print return value of the shellcode to the console

/**
 * The XOR password to use.
 */
static uint8_t StaticPassword[] = { 0xAA };

/**
 * The shellcode to use.
 * 
 * This is custom written shellcode. Yields an access denied (access violation).
 */
static uint8_t StaticShellcode[] = {
    0x48, 0x31, 0xC0,                   // xor rax, rax        ; Clear RAX register
    0x48, 0xC7, 0xC1, 0x01, 0x00, 0x00, 0x00, // mov rcx, 1     ; Move 1 into RCX (first argument)
    0x48, 0xC7, 0xC2, 0x02, 0x00, 0x00, 0x00, // mov rdx, 2     ; Move 2 into RDX (second argument)
    0x49, 0xC7, 0xC0, 0x03, 0x00, 0x00, 0x00, // mov r8, 3      ; Move 3 into R8 (third argument)
	0x48, 0xA1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // mov rax, [0xFFFFFFFFFFFFFFFF] ; Move the value at the address 0xFFFFFFFFFFFFFFFF into RAX
	0x48, 0xA1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // mov rax, [0xFFFFFFFFFFFFFFFF] ; Move the value at the address 0xFFFFFFFFFFFFFFFF into RAX
	0x48, 0xA1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF  // mov rax, [0xFFFFFFFFFFFFFFFF] ; Move the value at the address 0xFFFFFFFFFFFFFFFF into RAX
};
