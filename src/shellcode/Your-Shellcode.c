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
 * 
 *  ██████╗██╗   ██╗██████╗ ███████╗██████╗  ██████╗██╗  ██╗███████╗███████╗
 * ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║██╔════╝██╔════╝
 * ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║     ███████║█████╗  █████╗  
 * ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║     ██╔══██║██╔══╝  ██╔══╝  
 * ╚██████╗   ██║   ██████╔╝███████╗██║  ██║╚██████╗██║  ██║███████╗██║     
 *  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝     
 *                                                                     
 * Use this CyberChef command to XOR your shellcode and convert it to the format for this file (adjust XOR key if desired):
 * https://gchq.github.io/CyberChef/#recipe=Regular_expression('User%20defined','0x%5C%5Cw%7B2%7D',true,true,false,false,false,false,'List%20matches')Find_/_Replace(%7B'option':'Regex','string':'(.*)%5C%5Cn'%7D,'$1,',true,false,true,false)Remove_whitespace(true,true,true,true,true,false)From_Hex('Auto')XOR(%7B'option':'Hex','string':'AA41CC'%7D,'Standard',false)To_Hex('0x%20with%20comma',15)Find_/_Replace(%7B'option':'Regex','string':'((0x(%5C%5Cd%7C%5C%5Cw)%7B2%7D,?%5C%5Cn?)%2B)'%7D,'%23define%20STATIC_SHELLCODE_NAME%20%22Your-Shellcode%22%20//%20Name%20to%20be%20printed%20%5C%5Cn%23define%20STATIC_SHELLCODE_IS_ALREADY_ENCRYPTED%200x1%20//%20May%20only%20be%20negative%20for%20debugging%20purposes%20with%20plain%20static%20shellcode%20%5C%5Cn%23define%20STATIC_SHELLCODE_HAS_RETURN_VALUE%200x0%20//%20Print%20return%20value%20of%20the%20shellcode%20to%20the%20console%5C%5Cn%5C%5Cnstatic%20uint8_t%20StaticPassword%5B%5D%20%3D%20%7B%200xAA,%200x41,%200xCC%20%7D;%5C%5Cn%5C%5Cnstatic%20uint8_t%20StaticShellcode%5B%5D%20%3D%20%7B%5C%5Cn$1%5C%5Cn%7D;',true,false,true,true)Find_/_Replace(%7B'option':'Regex','string':'%5E0x'%7D,'%20%20%20%200x',true,false,true,false)&input=Ly8gVXNlIHRoZSBjb21tYW5kIGJlbG93IHRvIGdldCB0aGUgaW5wdXQgZm9yIHRoaXMgWE9SIGVuY29kaW5nIGJha2Ugd2l0aCBDeWJlckNoZWYKLy8geHhkIC1pIHlvdXItc2hlbGxjb2RlLmJpbgoKdW5zaWduZWQgY2hhciBfX195b3VyX3NoZWxsY29kZV9iaW5bXSA9IHsKICAweDU1LCAweDQ4LCAweDg5LCAweGU1LCAweGU4LCAweDhiLCAweDk3LCAweDAwLCAweDAwLCAweDkwLCAweDVkLCAweGMzLAogIDB4NTUsIDB4NDgsIDB4ODksIDB4ZTUsIDB4NDgsIDB4ODMsIDB4ZWMsIDB4MTAsIDB4YzcsIDB4NDUsIDB4ZmMsIDB4NjAsCiAgMHgwMCwgMHgwMCwgMHgwMCwgMHg4YiwgMHg0NSwgMHhmYywgMHg2NSwgMHg0OCwgMHg4YiwgMHgwMCwgMHg0OCwgMHg4OSwKICAweDQ1LCAweGYwLCAweDQ4LCAweDhiLCAweDQ1LCAweGYwLCAweGM5LCAweGMzLCAweDU1LCAweDQ4LCAweDg5LCAweGU1LAogIDB4NDgsIDB4ODksIDB4NGQsIDB4MTAsIDB4NDgsIDB4OGIsIDB4NDUsIDB4MTAsIDB4NDgsIDB4ODMsIDB4ZTgsIDB4MTAsCiAgMHg1ZCwgMHhjMywgMHg1NSwgMHg0OCwgMHg4OSwgMHhlNSwgMHg0OCwgMHg4OSwgMHg0ZCwgMHgxMCwgMHg0OCwgMHg4OQogIC4uLgp9Ow
 */

/**
 * Predefined definitions
 */
#define STATIC_SHELLCODE_NAME "Your-Shellcode" // Name to be printed 
#define STATIC_SHELLCODE_IS_ALREADY_ENCRYPTED 0x1 // May only be negative for debugging purposes with plain static shellcode 
#define STATIC_SHELLCODE_HAS_RETURN_VALUE 0x0 // Print return value of the shellcode to the console

/**
 * The XOR password to use.
 */
static uint8_t StaticPassword[] = { 0xAA, 0x41, 0xCC };

/**
 * The shellcode to use.
 */
static uint8_t StaticShellcode[] = {
	// Replace with your shellcode 
    0xe2,0xcc,0xc9,0xa7,0x41,0xcc,0xaa,0x4e,0x47,0xaa,0x09,0x41,0xb7,0x49,0xcc,
    0xaa,0x41,0xc5,0xa5,0xee,0xcf,0x69,0x43,0xcc,0xaa,0x41,0xcf,0xaa,0x41,0xcc
};