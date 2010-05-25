CFLAGS += -I../include/powerpc
CFLAGS += -Wa,-mregnames -I lib
CFLAGS += -ffreestanding

cstart := powerpc/cstart.o

cflatobjs += \
	lib/powerpc/io.o

$(libcflat): LDFLAGS += -nostdlib

# these tests do not use libcflat
simpletests := \
	powerpc/spin.bin \
	powerpc/io.bin \
	powerpc/sprg.bin

# theses tests use cstart.o, libcflat, and libgcc
tests := \
	powerpc/exit.bin \
	powerpc/helloworld.bin

include config-powerpc-$(PROCESSOR).mak


all: kvmtrace kvmctl $(libcflat) $(simpletests) $(tests)

$(simpletests): %.bin: %.o
	$(CC) -nostdlib $^ -Wl,-T,flat.lds -o $@

$(tests): %.bin: $(cstart) %.o $(libcflat)
	$(CC) -nostdlib $^ $(libgcc) -Wl,-T,flat.lds -o $@

kvmctl_objs = main-ppc.o iotable.o ../libkvm/libkvm.a

arch_clean:
	$(RM) $(simpletests) $(tests) $(cstart)
	$(RM) $(patsubst %.bin, %.elf, $(simpletests) $(tests))
	$(RM) $(patsubst %.bin, %.o, $(simpletests) $(tests))
