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
 * NTSTATUS Codes Header.
 * 
 * Definitions for NTSTATUS codes used in Windows operating systems.
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
 */
#include <ntstatus.h>

/**
 * Global definitions
 */
#define MAX_INSTRUCTION_ACTIONS_PER_BYTE 4 // We support up to 4 actions per instruction (related to the 4 registers of the x64 calling convention)

/**
 * Type definitions
 */
typedef void (*runnable)(void);
typedef uint8_t* (*runnableAndReturn)(void);

/**
 * Enum describing the type of a byte in the payload (as soon as it's known).
 */
enum ByteType {
    BYTE_TYPE_UNKNOWN,
    BYTE_TYPE_PART_OF_INSTRUCTION,
    BYTE_TYPE_PART_OF_DATA
};

/**
 * Enum describing a desired byte(sequence) state (either encrypted or decrypted).
 */
enum DesiredState {
    DESIRED_STATE_UNDEFINED,
    DESIRED_STATE_ENCRYPTED,
    DESIRED_STATE_DECRYPTED
};

/**
 * Struct describing an action to perform for a specific instruction address
 */
struct InstructionAction {
    enum DesiredState eDesiredState;
    uint8_t* lpAddress;
    uint64_t dwSize;
};

/**
 * Struct describing certain attributes of a specific byte in the payload.
 */
struct ByteDescriptor {
    uint8_t* lpLastKnownNextAddress;
    uint8_t* lpLastKnownNextBreakpointAddress;
    enum ByteType eByteType;
    bool bIsEncrypted;
    struct InstructionAction sInstructionActions[MAX_INSTRUCTION_ACTIONS_PER_BYTE];
};

/**
 * Struct describing the entire payload (its bytes, size, and byte descriptors).
 */
struct PayloadDescriptor {
    uint8_t* lpPayload;
    uint32_t dwPayloadSize;
    uint8_t* lpPassword;
    uint32_t dwPasswordSize;
    struct ByteDescriptor* lpBDL;
};

/**
 * Create an initialized ByteDescriptorList (BDL) containing a map of all bytes in the given shellcode (including the byte properties).
 * 
 * @param uint8_t* lpShellcode The shellcode to initialize the BDL with.
 * @param uint32_t dwShellcodeSize The length of the shellcode.
 * @param bool bShellcodeEncrypted Positive if the shellcode is already encrypted (must be the case for production runs).
 * @param struct ByteDescriptor** lpBDL Where the BDL is written to.
 * @return NTSTATUS Zero if succesfully initialized, error code otherwise.
 */
NTSTATUS CreateByteDescriptorList(uint8_t* lpShellcode, uint32_t dwShellcodeSize, bool bShellcodeEncrypted, struct ByteDescriptor** lpBDL) {
    struct ByteDescriptor* lpAddress = VirtualAlloc(
        NULL,                                               // Let the system determine the address
        sizeof(struct ByteDescriptor) * dwShellcodeSize,    // Size of the memory block
        MEM_COMMIT | MEM_RESERVE,                           // Allocate committed and reserved memory
        PAGE_READWRITE                                      // Read and write access
    );

    if (lpAddress == NULL) {
        return GetLastError();
    }

    for (uint32_t i = 0; i < dwShellcodeSize; i++) {
        lpAddress[i].bIsEncrypted = bShellcodeEncrypted;
        lpAddress[i].eByteType = BYTE_TYPE_UNKNOWN;
    }

    *lpBDL = lpAddress;
    return STATUS_SUCCESS;
}

/**
 * Create an initialized PayloadDescriptor (PL) containing the actual payload as well as metadata describing it.
 * 
 * @param uint8_t* lpShellcode The shellcode to initialize the BDL with.
 * @param uint32_t dwShellcodeSize The length of the shellcode.
 * @param uint8_t* lpPassword The password that was used to encrypt the payload.
 * @param uint32_t dwPasswordSize The length of the password.
 * @param bool bShellcodeEncrypted Positive if the shellcode is already encrypted (must be the case for production runs).
 * @param struct PayloadDescriptor* lpPD The PL that results are written to.
 * @return NTSTATUS Zero if succesfully initialized, error code otherwise.
 */
NTSTATUS CreatePayloadAndDescriptor(uint8_t* lpShellcode, uint32_t dwShellcodeSize, uint8_t* lpPassword, uint32_t dwPasswordSize, bool bShellcodeEncrypted, struct PayloadDescriptor* lpPD) {
    NTSTATUS dwResult;

    lpPD->lpPayload = VirtualAlloc(NULL, dwShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    lpPD->dwPayloadSize = dwShellcodeSize;
    lpPD->lpPassword = lpPassword;
    lpPD->dwPasswordSize = dwPasswordSize;

    if (lpPD->lpPayload == NULL) {
        PRINT_WARNING("Could not allocate lpPayload in CreatePayloadAndDescriptor(...).");
        return GetLastError();
    } else {
        MoveMemory(lpPD->lpPayload, lpShellcode, dwShellcodeSize);
    }

    if (NT_ERROR(dwResult = CreateByteDescriptorList((uint8_t*) &StaticShellcode, sizeof(StaticShellcode), STATIC_SHELLCODE_IS_ALREADY_ENCRYPTED, &lpPD->lpBDL))) {
        PRINT_WARNING("Could not create Byte Descriptor List (BDL) in CreatePayloadAndDescriptor(...).");
        return dwResult;
    }

    return STATUS_SUCCESS;
}

/**
 * Add byte type metadata to address range.
 * 
 * @param struct PayloadDescriptor* lpPD The payload descriptor that holds the payload and its metadata.
 * @param uint8_t* lpAddress The address to check (if it's within the bounds of the payload).
 * @return bool Positive if given address is within payload bounds.
 */
bool IsAddressWithinBounds(struct PayloadDescriptor* lpPD, uint8_t* lpAddress) {
    return lpAddress >= lpPD->lpPayload && lpAddress < (lpPD->lpPayload + lpPD->dwPayloadSize);
}

/**
 * Add byte type metadata to address range.
 * 
 * @param struct PayloadDescriptor* lpPD The payload descriptor that holds the payload and its metadata.
 * @param uint32_t dwOffset The offset to start setting the byte type at, within the payload.
 * @param uint32_t dwSize The amount of bytes to update (starting at the offset).
 * @param enum ByteType eByteType The type of byte to set for the address range.
 */
void SetByteType(struct PayloadDescriptor* lpPD, uint32_t dwOffset, uint32_t dwSize, enum ByteType eByteType) {
    for (uint32_t i = dwOffset; i < (dwOffset + dwSize); i ++) {
        lpPD->lpBDL[i].eByteType = eByteType;
    }
}

/**
 * Get the size of a string that is (possibly) encrypted in memory.
 * 
 * @param struct PayloadDescriptor* lpPD The payload descriptor that holds the payload and its metadata.
 * @param uint32_t dwOffset The offset that a string resides in encrypted memory.
 * @return uint64_t The calculated size of the encrypted string at the given offset.
 */
uint64_t GetEncryptedStringLength(struct PayloadDescriptor* lpPD, uint32_t dwOffset) {
    uint64_t qwSize = 0;

    for (uint32_t i = dwOffset; i < lpPD->dwPayloadSize; i ++) {
        if (lpPD->lpBDL[i].bIsEncrypted) {
            if ((lpPD->lpPayload[i] ^ lpPD->lpPassword[i % lpPD->dwPasswordSize]) == 0x00) {
                break;
            }
        } else {
            if (lpPD->lpPayload[i] == 0x00) {
                break;
            }
        }

        qwSize ++;
    }

    return qwSize;
}


/**
 * Toggle the encryption of certain bytes in the given payload.
 * 
 * @param struct PayloadDescriptor* lpPD The payload descriptor that holds the payload and its metadata.
 * @param uint32_t dwOffset The offset to start the encryption toggle at, within the payload.
 * @param uint32_t dwSize The amount of bytes to toggle (starting at the offset).
 */
void ToggleEncryption(struct PayloadDescriptor* lpPD, uint32_t dwOffset, uint32_t dwSize) {
    for (uint32_t i = dwOffset; i < (dwOffset + dwSize); i ++) {
        // If index is beyond payload range, ignore.
        // Index cannot be before payload range.
        if (i >= (dwOffset + dwSize) || i >= lpPD->dwPayloadSize) continue;

        lpPD->lpPayload[i] ^= lpPD->lpPassword[i % lpPD->dwPasswordSize];
        lpPD->lpBDL[i].bIsEncrypted = !lpPD->lpBDL[i].bIsEncrypted;
    }
}

/**
 * Encrypt certain bytes in the given payload.
 * 
 * @param struct PayloadDescriptor* lpPD The payload descriptor that holds the payload and its metadata.
 * @param uint32_t dwOffset The offset to start the encryption at, within the payload.
 * @param uint32_t dwSize The amount of bytes to encrypt (starting at the offset).
 * @param bool bSilent Ignore any bytes that are already encrypted if positive, throw error otherwise.
 */
void Encrypt(struct PayloadDescriptor* lpPD, uint32_t dwOffset, uint32_t dwSize, bool bSilent) {
    for (uint32_t i = dwOffset; i < (dwOffset + dwSize); i ++) {
        // If index is beyond payload range, ignore.
        // Index cannot be before payload range.
        if (i >= (dwOffset + dwSize) || i >= lpPD->dwPayloadSize) continue;

        if (!lpPD->lpBDL[i].bIsEncrypted) {
            lpPD->lpPayload[i] ^= lpPD->lpPassword[i % lpPD->dwPasswordSize];
            lpPD->lpBDL[i].bIsEncrypted = true;
        } else if (!bSilent) {
            PRINT_FAILURE_AND_ABORT("Byte at offset 0x%X was already encrypted in Encrypt(...).", i);
        }
    }
}

/**
 * Decrypt certain bytes in the given payload.
 * 
 * @param struct PayloadDescriptor* lpPD The payload descriptor that holds the payload and its metadata.
 * @param uint32_t dwOffset The offset to start the decryption at, within the payload.
 * @param uint32_t dwSize The amount of bytes to decrypt (starting at the offset).
 * @param bool bSilent Ignore any bytes that are already decrypted if positive, throw error otherwise.
 */
void Decrypt(struct PayloadDescriptor* lpPD, uint32_t dwOffset, uint32_t dwSize, bool bSilent) {
    for (uint32_t i = dwOffset; i < (dwOffset + dwSize); i ++) {
        // If index is beyond payload range, ignore.
        // Index cannot be before payload range.
        if (i >= (dwOffset + dwSize) || i >= lpPD->dwPayloadSize) continue;
        
        if (lpPD->lpBDL[i].bIsEncrypted) {
            lpPD->lpPayload[i] ^= lpPD->lpPassword[i % lpPD->dwPasswordSize];
            lpPD->lpBDL[i].bIsEncrypted = false;
        } else if (!bSilent) {
            PRINT_FAILURE_AND_ABORT("Byte at offset 0x%X was already decrypted in Decrypt(...).", i);
        }
    }
}