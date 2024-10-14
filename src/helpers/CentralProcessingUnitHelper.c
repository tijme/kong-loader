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
 * Include Zydis.
 * 
 * Fast and lightweight x86/x86-64 disassembler and code generation library.
 * https://github.com/zyantific/zydis
 */
#include <Zydis/Zydis.h>

/**
 * Obtain the given eflag from the given thread context.
 * 
 * @param PCONTEXT lpContext The context of a specific thread.
 * @param uint32_t The eflag to obtain from the thread context.
 * @return bool Positive if the flag is set, negative otherwise.
 */
bool getCpuFlagValue(PCONTEXT lpContext, uint32_t eflag) {
    switch (eflag) {
        case ZYDIS_CPUFLAG_OF: return (lpContext->EFlags & 0x00000400) != 0; break;
        case ZYDIS_CPUFLAG_IF: return (lpContext->EFlags & 0x00000200) != 0; break;
        case ZYDIS_CPUFLAG_SF: return (lpContext->EFlags & 0x00000080) != 0; break;
        case ZYDIS_CPUFLAG_ZF: return (lpContext->EFlags & 0x00000040) != 0; break;
        case ZYDIS_CPUFLAG_AF: return (lpContext->EFlags & 0x00000010) != 0; break;
        case ZYDIS_CPUFLAG_PF: return (lpContext->EFlags & 0x00000004) != 0; break;
        case ZYDIS_CPUFLAG_CF: return (lpContext->EFlags & 0x00000001) != 0; break;
        default:
            PRINT_FAILURE_AND_ABORT("Unknown eflag 0x%X in getCpuFlagValue().", eflag);
    }
}

/**
 * Obtain the value of the given register from the given thread context.
 * 
 * @param PCONTEXT lpContext The context of a specific thread.
 * @param ZydisRegister zdKey The register to obtain the value from using the thread context.
 * @return uint64_t The actual value of the given register.
 */
uint64_t getCpuRegisterValue(PCONTEXT lpContext, ZydisRegister zdKey) {
    switch (zdKey) {
        case ZYDIS_REGISTER_RAX: return lpContext->Rax; break;
        case ZYDIS_REGISTER_RCX: return lpContext->Rcx; break;
        case ZYDIS_REGISTER_RDX: return lpContext->Rdx; break;
        case ZYDIS_REGISTER_RBX: return lpContext->Rbx; break;
        case ZYDIS_REGISTER_RSP: return lpContext->Rsp; break;
        case ZYDIS_REGISTER_RBP: return lpContext->Rbp; break;
        case ZYDIS_REGISTER_RSI: return lpContext->Rsi; break;
        case ZYDIS_REGISTER_RDI: return lpContext->Rdi; break;
        case ZYDIS_REGISTER_RIP: return lpContext->Rip; break;
        case ZYDIS_REGISTER_R8:  return lpContext->R8;  break;
        case ZYDIS_REGISTER_R9:  return lpContext->R9;  break;
        case ZYDIS_REGISTER_R10: return lpContext->R10; break;
        case ZYDIS_REGISTER_R11: return lpContext->R11; break;
        case ZYDIS_REGISTER_R12: return lpContext->R12; break;
        case ZYDIS_REGISTER_R13: return lpContext->R13; break;
        case ZYDIS_REGISTER_R14: return lpContext->R14; break;
        case ZYDIS_REGISTER_R15: return lpContext->R15; break;
        default:
            PRINT_FAILURE_AND_ABORT("Registry key 0x%X not (yet) defined in getCpuRegisterValue() switch statement.", zdKey);
    }
}

/**
 * Obtain the argument index of a function based on Zydis register.
 * 
 * @param ZydisRegister zdKey The register to obtain the argument index for.
 * @return uint32_t The argument index based on the x64 calling convention (CC).
 */
uint32_t getCCArgumentIndexFromRegister(ZydisRegister zdKey) {
    switch (zdKey) {
        case ZYDIS_REGISTER_RCX: return 0; break;
        case ZYDIS_REGISTER_RDX: return 1; break;
        case ZYDIS_REGISTER_R8: return 2; break;
        case ZYDIS_REGISTER_R9: return 3; break;
        default:
            PRINT_FAILURE_AND_ABORT("Unknown argument index based on Zydis register 0x%X.", zdKey);
    }
}

/**
 * Obtain the register of a function based on an argument index.
 * 
 * @param uint32_t dwArgumentIndex The argument index to obtain the register for.
 * @return ZydisRegister The register belonging to the argument index based on the x64 calling convention (CC).
 */
ZydisRegister getCCRegisterFromArgumentIndex(uint32_t dwArgumentIndex) {
    switch (dwArgumentIndex) {
        case 0: return ZYDIS_REGISTER_RCX; break;
        case 1: return ZYDIS_REGISTER_RDX; break;
        case 2: return ZYDIS_REGISTER_R8; break;
        case 3: return ZYDIS_REGISTER_R9; break;
        default:
            PRINT_FAILURE_AND_ABORT("Unknown Zydis register based on argument index 0x%X.", dwArgumentIndex);
    }
}

/**
 * Configure a breakpoint in the debug registers.
 * 
 * @param PCONTEXT lpContext A thread context during a vectored exception.
 * @param uint8_t* dwAddress The address to breakpoint on.
 */
void SetBreakpoint(PCONTEXT lpContext, uint8_t* dwAddress) {
    if (dwAddress != NULL) {
        lpContext->Dr0 = (DWORD64) dwAddress;
        lpContext->Dr7 = 0x0000000000000001; // Enable breakpoint
        lpContext->Dr7 &= ~(1 << 16); // On execution only (not read/write)
    } else {
        lpContext->Dr0 = 0x0000000000000000;
        lpContext->Dr7 = 0x0000000000000000;
    }
}
