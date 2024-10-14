# Mozilla Public License (MPL) Version 2.0.
#
# Copyright (c) 2024 Tijme Gommers (@tijme).
#
# This source code file is part of Kong Loader. Kong Loader is 
# licensed under Mozilla Public License (MPL) Version 2.0, and 
# you are free to use, modify, and distribute this file under 
# its terms. However, any modified versions of this file must 
# include this same license and copyright notice.

CC_X64 := x86_64-w64-mingw32-gcc
TARGET := KongLoader

.PHONY: all clean ./dst/$(TARGET).x64.exe 

all: ./dst/$(TARGET).x64.exe 

clean:
	rm -f ./dst/$(TARGET).*
	
./dst/$(TARGET).x64.exe:
	$(CC_X64) ./src/$(TARGET).c -o ./dst/$(TARGET).x64.exe -masm=intel -I inc -ldbghelp -lkernel32 -luser32 -lntdll -lole32 -loleaut32
