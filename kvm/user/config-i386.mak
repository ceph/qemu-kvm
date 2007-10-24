LIBDIR = /lib
cstart.o = test/cstart.o
bits = 32
ldarch = elf32-i386
CFLAGS += -m32
CFLAGS += -D__i386__
CFLAGS += -I $(KERNELDIR)/include

flatfile_tests=

include config-x86-common.mak
