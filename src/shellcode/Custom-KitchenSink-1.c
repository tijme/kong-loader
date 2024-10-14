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
 * This is custom written shellcode. It performs various simple operations.
 */
static uint8_t StaticShellcode[] = {
    // main()
    0xE8, 0x10, 0x00, 0x00, 0x00, // call test_jmp_and_jl (relative offset)
    0xE8, 0x2A, 0x00, 0x00, 0x00, // call test_je (relative offset)
    0xE8, 0x3E, 0x00, 0x00, 0x00, // call test_jne (relative offset
    0xE8, 0x52, 0x00, 0x00, 0x00, // call test_loop (relative offset
    0xC3,                         // ret

    // FUNCTION: test_jmp_and_jl()
        // start
        // jumps over nops
        0xEB, 0x04,                   // jmp short to skip over the nops
        0x90,                         // nop
        0x90,                         // nop
        0x90,                         // nop
        0x90,                         // nop
        
        // test_jmp_and_jl() + nops
        // jmp to 
        0x31, 0xC0,                   // xor eax, eax   ; clear eax (set to zero)
        0xB8, 0x41, 0x00, 0x00, 0x00, // mov eax 0x41
        0x83, 0xF8, 0x42,             // cmp eax, 0x42  ; compare eax with 0x42
        0x7C, 0x07,                   // jl short less_than  ; jump if less than

        // test_jmp_and_jl() + eax >= 0x42
        // does not execute
        // moves 0xAAAAAAAA to eax
        0xB8, 0xAA, 0xAA, 0xAA, 0xAA, // mov eax, 0xAAAAAAAA
        0xEB, 0x05,                   // jmp short end_jl

        // test_jmp_and_jl() + eax < 0x42
        // moves 0x13371337 to eax
        0xB8, 0x37, 0x13, 0x37, 0x13, // mov eax, 0x13371337

        // test_jmp_and_jl() + end_jl
        0xC3,                         // end_jl: ret

    // FUNCTION test_je()
        0x31, 0xC0,                   // xor eax, eax   ; clear eax (set to zero)
        0xB8, 0x30, 0x00, 0x00, 0x00, // mov eax 0x30
        0x83, 0xF8, 0x30,             // cmp eax, 0x30  ; compare eax with 0x42
        0x74, 0x07,                   // je short equal_to  ; jump if equal
    
        // test_je() + eax != 0x30
        0xB8, 0xBB, 0xBB, 0xBB, 0xBB, // mov eax, 0xBBBBBBBB
        0xEB, 0x05,                   // jmp short end_jl

        // test_je() + eax == 0x30
        // moves 0x13371337 to eax
        0xB8, 0x37, 0x13, 0x37, 0x13, // ov eax, 0x13371337

        // test_je() + end_je
        0xC3,                         // end_je: ret

    // FUNCTION test_jne()
        0x31, 0xC0,                   // xor eax, eax   ; clear eax (set to zero)
        0xB8, 0x30, 0x00, 0x00, 0x00, // mov eax 0x30
        0x83, 0xF8, 0x30,             // cmp eax, 0x30  ; compare eax with 0x42
        0x75, 0x07,                   // jne short equal_to  ; jump if equal
    
        // test_jne() + eax == 0x30
        0xB8, 0x37, 0x13, 0x37, 0x13, // mov eax, 0x13371337
        0xEB, 0x05,                   // jmp short end_jl

        // test_jne() + eax != 0x30
        // moves 0x13371337 to eax
        0xB8, 0xCC, 0xCC, 0xCC, 0xCC, // mov eax, 0xCCCCCCCC

        // test_jne() + end_jne
        0xC3,                         // end_jne: ret

    // FUNCTION test_loop()
        0x31, 0xC9,                   // xor ecx, ecx   ; clear ecx (set to zero)
        0xB1, 0x05,                   // mov cl, 0x05   ; set ecx to 5
        0x90,                         // nop            ; do nothing
        0x90,                         // nop            ; do nothing
        0x90,                         // nop            ; do nothing
        0x90,                         // nop            ; do nothing
        0x90,                         // nop            ; do nothing
        0xE2, 0xF9,                   // loop -0x07     ; loop to the beginning of nops
        0xC3                          // ret
};