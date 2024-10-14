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
 * Time handling.
 * 
 * Defines macros, types, and functions for manipulating date and time.
 * https://pubs.opengroup.org/onlinepubs/007908799/xsh/time.h.html
 */
#include <time.h>

/**
 * Local definitions
 */
#ifndef ENABLE_VERBOSE_PRINT_STATEMENTS
#define ENABLE_VERBOSE_PRINT_STATEMENTS 0x0 // Verbose printing (if positive)
#endif

/**
 * Console color codes
 */
#define COLOR_RESET "\x1b[0m"
#define COLOR_GREEN "\x1b[32m"
#define COLOR_YELLOW "\x1b[33m"
#define COLOR_RED "\x1b[31m"

/**
 * Define print methods
 */
#define PRINT(...) { \
    time_t tNow; time(&tNow);  struct tm* lpNow = localtime(&tNow); \
    fprintf(stdout, "[INSIGHT %02d:%02d:%02d] ", lpNow->tm_hour, lpNow->tm_min, lpNow->tm_sec); \
    fprintf(stdout, __VA_ARGS__); \
    fprintf(stdout, "\n"); \
    fflush(stdout); \
}

#define PRINT_SUCCESS(...) { \
    time_t tNow; time(&tNow);  struct tm* lpNow = localtime(&tNow); \
    fprintf(stdout, COLOR_GREEN); \
    fprintf(stdout, "[SUCCESS %02d:%02d:%02d] ", lpNow->tm_hour, lpNow->tm_min, lpNow->tm_sec); \
    fprintf(stdout, __VA_ARGS__); \
    fprintf(stdout, "\n"); \
    fprintf(stdout, COLOR_RESET); \
    fflush(stdout); \
}

#define PRINT_WARNING(...) { \
    time_t tNow; time(&tNow);  struct tm* lpNow = localtime(&tNow); \
    fprintf(stdout, COLOR_YELLOW); \
    fprintf(stdout, "[WARNING %02d:%02d:%02d] ", lpNow->tm_hour, lpNow->tm_min, lpNow->tm_sec); \
    fprintf(stdout, __VA_ARGS__); \
    fprintf(stdout, "\n"); \
    fprintf(stdout, COLOR_RESET); \
    fflush(stdout); \
}

#define PRINT_FAILURE_AND_ABORT(...) { \
    time_t tNow; time(&tNow);  struct tm* lpNow = localtime(&tNow); \
    fprintf(stdout, COLOR_RED); \
    fprintf(stdout, "[FAILURE %02d:%02d:%02d] ", lpNow->tm_hour, lpNow->tm_min, lpNow->tm_sec); \
    fprintf(stdout, __VA_ARGS__); \
    fprintf(stdout, "\n"); \
    fprintf(stdout, COLOR_RESET); \
    fflush(stdout); \
    abort(); \
}

#define PRINT_VERBOSE(...) { \
    if (ENABLE_VERBOSE_PRINT_STATEMENTS) { \
        time_t tNow; time(&tNow);  struct tm* lpNow = localtime(&tNow); \
        fprintf(stdout, "[VERBOSE %02d:%02d:%02d] ", lpNow->tm_hour, lpNow->tm_min, lpNow->tm_sec); \
        fprintf(stdout, __VA_ARGS__); \
        fprintf(stdout, "\n"); \
        fflush(stdout); \
    } \
}

/**
 * Print a banner showing `Kong Loader`.
 */
void PrintBanner() {
    puts("");
    puts("888    d8P                                  888                            888                  ");
    puts("888   d8P                                   888                            888                  ");
    puts("888  d8P                                    888                            888                  ");
    puts("888d88K      .d88b.  88888b.   .d88b.       888      .d88b.   8888b.   .d88888  .d88b.  888d888 ");
    puts("8888888b    d88\"\"88b 888 \"88b d88P\"88b      888     d88\"\"88b     \"88b d88\" 888 d8P  Y8b 888P\"   ");
    puts("888  Y88b   888  888 888  888 888  888      888     888  888 .d888888 888  888 88888888 888     ");
    puts("888   Y88b  Y88..88P 888  888 Y88b 888      888     Y88..88P 888  888 Y88b 888 Y8b.     888     ");
    puts("888    Y88b  \"Y88P\"  888  888  \"Y88888      88888888 \"Y88P\"  \"Y888888  \"Y88888  \"Y8888  888     ");
    puts("                                   888                                                          ");
    puts("     The ART of rolling       Y8b d88P         Version 1.0 - Copyright 2024 Tijme Gommers       ");
    puts("    shellcode decryption       \"Y88P\"               Mozilla Public License (MPL)-2.0           ");
    puts("");
}

/**
 * Print given value in HEX
 * 
 * @param uint8_t* value An array of chars to print in HEX.
 * @param size_t length The amount of bytes/chars to print.
 * @param bool reverse Reverse the output (e.g. for a pointer).
 */
void PrintInHex(uint8_t* lpBuffer, size_t lpNumberOfBytesRead, bool reverse) {
    for(size_t i = 0; i < lpNumberOfBytesRead; i ++) {
        size_t indexCorrected = reverse ? lpNumberOfBytesRead - i - 1 : i;
        printf("%02X ", lpBuffer[indexCorrected] & 0xff);
    }

    printf("\n");
}
