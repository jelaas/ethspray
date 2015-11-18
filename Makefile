CC=musl-gcc-x86_32
CFLAGS=-Wall -std=c99 -D_POSIX_SOURCE

all:	ethspray ethsprayd
ethspray:	ethspray.o jelist.o jelopt.o
ethsprayd:	ethsprayd.o jelopt.o
clean:	
	rm -f *.o ethspray ethsprayd
rpm:	ethspray ethsprayd
	strip ethspray ethsprayd
	bar -c --license=GPLv2+ --name ethspray ethspray-1.5-1.rpm --prefix=/usr/bin --fuser=root --fgroup=root --version=1.5 --release=1 ethspray ethsprayd
