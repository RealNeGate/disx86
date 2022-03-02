call "W:\Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"

clang -march=nehalem -g -gcodeview -O2 -DNDEBUG -Werror -Wall -Wno-unused-function src/main.c src/disx86.c -o build/test.exe
