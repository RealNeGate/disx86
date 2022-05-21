rm -rf build
mkdir -p build
gcc src/main.c src/disx86.c -g -o build/disx86
gcc src/hexbin.c -g -o build/hexbin
./build/hexbin tests/bintest.txt build/bintest.bin
