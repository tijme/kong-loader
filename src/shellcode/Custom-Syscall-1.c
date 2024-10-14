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
#define STATIC_SHELLCODE_NAME "Custom-KitchenSink-1" // Name to be printed
#define STATIC_SHELLCODE_IS_ALREADY_ENCRYPTED 0x0 // May only be negative for debugging purposes with plain static shellcode
#define STATIC_SHELLCODE_HAS_RETURN_VALUE 0x1 // Print return value of the shellcode to the console

/**
 * The XOR password to use.
 */
static uint8_t StaticPassword[] = { 0xAA };

/**
 * The shellcode to use.
 * 
 * This is custom written shellcode. It calls NtTerminateProcess using a syscall
 */
static uint8_t StaticShellcode[] = {
    // Setup syscall for NtTerminateProcess
    0x4C, 0x8B, 0xD1,                  // mov r10, rcx          ; Move rcx to r10 (for syscall convention)
    0xB8, 0x2C, 0x00, 0x00, 0x00,      // mov eax, 0x2C         ; Syscall number for NtTerminateProcess
    0xBA, 0xFF, 0xFF, 0xFF, 0xFF,      // mov edx, 0xFFFFFFFF   ; Handle for current process (-1)
    0x48, 0x31, 0xF6,                  // xor rsi, rsi          ; Exit status 0 (STATUS_SUCCESS)
    0x0F, 0x05,                        // syscall               ; Perform syscall
    0xC3                               // ret                   ; Return
};