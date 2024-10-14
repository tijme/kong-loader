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
#define STATIC_SHELLCODE_NAME "Custom-ArgumentAsString-1" // Name to be printed
#define STATIC_SHELLCODE_IS_ALREADY_ENCRYPTED 0x0 // May only be negative for debugging purposes with plain static shellcode
#define STATIC_SHELLCODE_HAS_RETURN_VALUE 0x1 // Print return value of the shellcode to the console

/**
 * The XOR password to use.
 */
static uint8_t StaticPassword[] = { 0xAA };

/**
 * The shellcode to use.
 * 
 * This is custom written shellcode. It calls a non-existing function outside the shellcode, with a string as argument.
 */
static uint8_t StaticShellcode[] = {
    0x48, 0x8D, 0x0D, 0x05, 0x00, 0x00, 0x00,  // lea rcx, [rip+0xA] ; Address of "hello" in rcx
    0xE8, 0xF0, 0xFF, 0xFF, 0xFF,              // call <some function outside shellcode> ; Relative call
    0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x00         // "hello\0" ; Null-terminated string at the end
};