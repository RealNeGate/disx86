mkdir -p build
xxd -r -p tests/bintest.txt build/bintest.bin
gcc src/main.c src/disx86.c -g -o build/disx86
