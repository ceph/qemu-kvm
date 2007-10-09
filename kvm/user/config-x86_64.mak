LIBDIR = /lib64
cstart.o = test/cstart64.o
bits = 64
ldarch = elf64-x86-64
CFLAGS += -m64

flatfiles = test/access.flat test/irq.flat test/sieve.flat test/simple.flat test/stringio.flat test/memtest1.flat
