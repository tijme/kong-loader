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
#define STATIC_SHELLCODE_NAME "Custom-Multiply-1" // Name to be printed
#define STATIC_SHELLCODE_IS_ALREADY_ENCRYPTED 0x0 // May only be negative for debugging purposes with plain static shellcode
#define STATIC_SHELLCODE_HAS_RETURN_VALUE 0x1 // Print return value of the shellcode to the console

/**
 * The XOR password to use.
 */
static uint8_t StaticPassword[] = { 0xAA };

/**
 * The shellcode to use.
 * 
 * This is custom written shellcode. Performs a multiplication.
 */
static uint8_t StaticShellcode[] = {
// uint8_t* main()
    0x48, 0x8D, 0x05, 0x0D, 0x00, 0x00, 0x00,  // lea rax, [rip + 0x0F]    ; Load address of the first operand
    0x8B, 0x00,                                // mov eax, [rax]           ; Move the first operand into EAX
    0x48, 0x8D, 0x1D, 0x08, 0x00, 0x00, 0x00,  // lea rbx, [rip + 0x09]    ; Load address of the second operand
    0x0F, 0xAF, 0x03,                          // imul eax, [rbx]          ; Multiply EAX by the value at [RBX] (EAX = EAX * [RBX])
    0xC3,                                      // ret                      ; Return with the result in EAX

// Operands storage
    0x02, 0x00, 0x00, 0x00,                    // First operand: 2
    0x03, 0x00, 0x00, 0x00                     // Second operand: 3
};