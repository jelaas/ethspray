CC=musl-gcc-x86_32
CFLAGS=-Wall -std=c99 -D_POSIX_SOURCE

all:	ethspray ethsprayd
ethspray:	ethspray.o jelist.o jelopt.o
ethsprayd:	ethsprayd.o jelopt.o
clean:	
	rm -f *.o ethspray ethsprayd
