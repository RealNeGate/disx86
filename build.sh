rm -rf build

mkdir build

DISKIT=build/disx86
mkdir $DISKIT
mkdir $DISKIT/lib
mkdir $DISKIT/include

gcc -c -fPIC src/disx86.c -g -o build/disx86.o
ar rcs $DISKIT/lib/libdisx86.a build/disx86.o
cp src/disx86.h $DISKIT/include/.
cp src/public.inc $DISKIT/include/.
echo 'library kit @ '$(echo ./$DISKIT/)

gcc src/main.c src/elf.c $DISKIT/lib/libdisx86.a -g -o build/dis
gcc src/hexbin.c -g -o build/hexbin
./build/hexbin tests/bintest.txt build/bintest.bin
