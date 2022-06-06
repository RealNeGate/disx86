call vcvars64

mkdir build
clang -march=nehalem -g -gcodeview -Werror -Wall -Wno-unused-function -D_CRT_SECURE_NO_WARNINGS src/main.c src/elf.c src/disx86.c -o build/test.exe
clang -g -gcodeview -Werror -Wall -Wno-unused-function -D_CRT_SECURE_NO_WARNINGS src/hexbin.c -o build/hexbin.exe

build\hexbin.exe tests/bintest.txt build/bintest.bin
rem cl src/main.c src/disx86.c /MT /Zi /Fe:build\test.exe
