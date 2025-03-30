<p align="center">
    <img src="https://gist.githubusercontent.com/tijme/ce0ad845cfaaa0fb9a1897dca8dcc4e8/raw/20a617fed67d0f0f1d05f1d079704b6965fe9fc5/KongLoaderBanner.svg" alt="Kong Loader Banner" />
</p>
<p align="center">
    <a href="https://github.com/tijme/kong-loader/blob/master/LICENSE.md">
        <img src="https://img.shields.io/badge/License-MPL%20V2.0-527c50?style=for-the-badge&labelColor=2b4e34" />
    </a> &nbsp;
    <a href="https://github.com/tijme/kong-loader/releases">
        <img src="https://img.shields.io/github/v/release/tijme/kong-loader?style=for-the-badge&labelColor=2b4e34&color=527c50&cache=1" />
    </a> &nbsp;
    <a href="https://github.com/tijme/kong-loader/actions">
        <img src="https://img.shields.io/github/actions/workflow/status/tijme/kong-loader/compile.yml?style=for-the-badge&labelColor=2b4e34&color=527c50" />
    </a>
</p>
<p align="center">
    <b>The hidden ART of rolling shellcode decryption.</b>
    <br/>
    <sup>Built with ♥ by <a href="https://x.com/tijme">Tijme Gommers</a> – Buy me a coffee via <a href="https://www.paypal.me/tijmegommers">PayPal</a>.</sup>
    <br/>
</p>
<p align="center">
    <a href="#abstract">Abstract</a>
    •
    <a href="#getting-started">Getting started</a>
    •
    <a href="#caveats">Caveats</a>
    •
    <a href="#future-work">Future work</a>
    •
    <a href="#issues--requests">Issues & requests</a>
    •
    <a href="#license--copyright">License & copyright</a>
</p>
<hr>

## Abstract

Executing malicious shellcode may trigger memory scans by EDR, leading to detection of your malware. Sleep masks were introduced to ensure that your malware is encrypted in memory while it's idle (sleeping), aiming to prevent that detection. Using sleep masks, your malware is decrypted after sleeping, executes commands, and is then encrypted and instructed to sleep again. This ensures that your malware is only briefly visible in memory.

**Kong Loader** prevents your malware from being visible in memory *entirely* and *whatsoever*, even while executing commands. It uses rolling decryption, terminology I'm likely misusing, but which *does* represent how Kong Loader works. For each assembly instruction, Kong Loader decrypts that specific assembly instruction, executes it, and encrypts it again. This means only the currently executing instruction is visible in memory, which is insufficient for EDR to trigger detection on.

## Getting started

Clone this repository first. Install the dependencies, then [review the code](https://github.com/tijme/kong-loader/blob/master/.github/laughing.gif) and compile it from source. The steps below were tested on MacOS x64 and arm64.

**Dependencies**

* [MinGW](https://formulae.brew.sh/formula/mingw-w64)

**Compiling**

    make

**Usage**

Execute `./dst/KongLoader.x64.exe` on your Windows target machine.

## Caveats

There are various caveats, for both offensive & defensive cyber security. Some examples:

* Memory corruptions might occur if the shellcode tries to alter itself during runtime. 
* Kong Loader's native code can be signatured and thus easily detected.
* The execution is extremely slow, and can currently only be used for tiny first stage malware.
* Malware that runs using Kong Loader can be hardly debugged.
    - Exceptions trigger in your debugger, for every single instruction.
    - Exceptions can't be dismissed, as they decrypt the instruction to be executed.
    - Ignoring the exceptions using `sxi sse` (windbg) adds millions of instructions per instruction to be executed.
* Multi-threading is not supported as encryption race conditions would occur.

## Detection

At this moment, it is quite easy to detect Kong Loader because Kong Loader's native code is static and can therefore be signatured. There is no polymorphic engine yet that modifies the static code during each build. The following files contains rules that allows you to detect Kong Loader:

* [`kong_loader_native_code.yara` (Yara)](https://github.com/tijme/kong-loader/blob/master/sig/kong_loader_native_code.yara)

## Future work

* Write a shellcode transpiler that transpiles to a interpretable format that prevents the need of a disassembler.
    - This essentialy moves the Kong Loader funcionality from runtime to compile time.
* Possibly decrypt full basic blocks instead of single instructions, to improve speed.
* Make use of a polymorphic engine to ensure that the native code does not contain static signatures.

## Issues & requests

Issues or new feature requests can be reported via the [issue tracker](https://github.com/tijme/kong-loader/issues). Please make sure your issue or feature has not yet been reported by anyone else before submitting a new one.

## License & copyright

Copyright (c) 2024 Tijme Gommers. Kong Loader is released under the Mozilla Public License Version 2.0. View [LICENSE.md](https://github.com/tijme/kong-loader/blob/master/LICENSE.md) for the full license. Kong Loader depends on [Zydis](https://zydis.re/), which is licenced under the [MIT Licence](https://github.com/zyantific/zydis/blob/master/LICENSE).
