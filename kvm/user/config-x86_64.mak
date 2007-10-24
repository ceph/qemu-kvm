LIBDIR = /lib64
cstart.o = test/cstart64.o
bits = 64
ldarch = elf64-x86-64
CFLAGS += -m64
CFLAGS += -D__x86_64__
CFLAGS += -I $(KERNELDIR)/include

flatfile_tests = test/access.flat test/irq.flat test/sieve.flat test/simple.flat test/stringio.flat test/memtest1.flat

include config-x86-common.mak
