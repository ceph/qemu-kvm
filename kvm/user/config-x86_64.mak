LIBDIR = /lib64
TEST_DIR=test/x86
cstart.o = $(TEST_DIR)/cstart64.o
bits = 64
ldarch = elf64-x86-64
CFLAGS += -m64
CFLAGS += -D__x86_64__
CFLAGS += -I $(KERNELDIR)/include

tests = test/x86/access.flat test/x86/irq.flat test/x86/sieve.flat \
      test/x86/simple.flat test/x86/stringio.flat test/x86/memtest1.flat

include config-x86-common.mak
