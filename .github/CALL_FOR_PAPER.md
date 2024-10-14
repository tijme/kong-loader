# CFP

## Title

The hidden ART of rolling shellcode decryption

## Duration

30 minutes

## Banner

![Banner](https://raw.githubusercontent.com/tijme/kong-loader/master/.github/banner.png)

## Abstract

Executing malicious shellcode may trigger memory scans by EDR, leading to detection of malware. Sleep masks were introduced to ensure that malware is encrypted in memory while it's idle (sleeping), aiming to prevent that detection. Using sleep masks, malware is decrypted after sleeping, executes commands, and is then encrypted and instructed to sleep again. This ensures that the malware is only briefly visible in memory.

In this talk, I'll introduce Kong Loader, a completely new concept of loading shellcode. Kong Loader prevents malware from being visible in memory *entirely* and *whatsoever*, even while executing commands. For each assembly instruction, Kong Loader decrypts that specific assembly instruction, executes it, and encrypts it again. This means only the currently executing instruction is visible in memory.

It comes with dangerous benefits for offensive security experts, and with new complex challenges for defenders & malware analysts. This briefing covers that all, and Kong Loader will be published during the briefing, so you can start experimenting with it yourself.
