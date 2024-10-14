rule KongLoader
{
    meta:
        description = "Detects binaries that import AddVectoredExceptionHandler, ZydisDecoderDecodeFull and call VirtualAlloc with PAGE_EXECUTE_READWRITE"
        author = "Tijme Gommers"
        date = "2024-10-14"
        reference = "https://github.com/tijme/kong-loader"

    strings:
        // Look for import of AddVectoredExceptionHandler
        $import_AddVectoredExceptionHandler = { 41 64 64 56 65 63 74 6F 72 65 64 45 78 63 65 70 74 69 6F 6E 48 61 6E 64 6C 65 72 }

        // Look for import of ZydisDecoderDecodeFull
        $import_ZydisDecoderDecodeFull = { 5A 79 64 69 73 44 65 63 6F 64 65 72 44 65 63 6F 64 65 46 75 6C 6C }

        // Look for call to VirtualAlloc with PAGE_EXECUTE_READWRITE (0x40)
        $call_VirtualAlloc_PAGE_EXECUTE_READWRITE =  { 
            41 B9 40 00 00 00      // push 0x40 (PAGE_EXECUTE_READWRITE)
            41 B8 00 30 00 00      // push 0x3000 (MEM_COMMIT | MEM_RESERVE)
            ?? ?? ??               // push <variable size> (dwShellcodeSize)
            B9 00 00 00 00         // push 0x0 (NULL)
            48 8B 05 ?? ?? ?? ??   // mov rax, VirtualAlloc
            FF D0                  // call rax
        }

    condition:
        all of ($import_*) and $call_VirtualAlloc_PAGE_EXECUTE_READWRITE
}