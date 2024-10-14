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
#define STATIC_SHELLCODE_NAME "Custom-Storage-1" // Name to be printed
#define STATIC_SHELLCODE_IS_ALREADY_ENCRYPTED 0x0 // May only be negative for debugging purposes with plain static shellcode
#define STATIC_SHELLCODE_HAS_RETURN_VALUE 0x1 // Print return value of the shellcode to the console

/**
 * The XOR password to use.
 */
static uint8_t StaticPassword[] = { 0xAA };

/**
 * The shellcode to use.
 * 
 * This is custom written shellcode. It calls another a piece of shellcode on the heap, mimicking encrypted argument use.
 */
static uint8_t StaticShellcode[] = {
// uint8_t* main()
    0x48, 0x8D, 0x0D, 0x0D, 0x00, 0x00, 0x00,        // lea rcx, [rip + 0x0D]
    0xE8, 0x01, 0x00, 0x00, 0x00,                    // call get_return_value(rcx)
    0xC3,                                            // ret

// uint8_t* get_return_value()
    0x4C, 0x8B, 0x01,                                // mov r8, [rcx]    ; load the value into r8
    0x4C, 0x89, 0xC0,                                // mov rax, r8
    0xC3,                                            // ret

// return value storage
    0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13   // 0x13371337.13371337
};