platform := 44x

CFLAGS += -m32
CFLAGS += -D__powerpc__
CFLAGS += -I $(KERNELDIR)/include
CFLAGS += -Wa,-mregnames -I test/lib

cstart := test/powerpc/cstart.o

cflatobjs += \
	test/lib/powerpc/io.o

$(libcflat): LDFLAGS += -nostdlib
$(libcflat): CFLAGS += -ffreestanding

# these tests do not use libcflat
simpletests := \
	test/powerpc/spin.bin \
	test/powerpc/io.bin \
	test/powerpc/sprg.bin

# theses tests use cstart.o, libcflat, and libgcc
tests := \
	test/powerpc/exit.bin

include config-powerpc-$(platform).mak


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
