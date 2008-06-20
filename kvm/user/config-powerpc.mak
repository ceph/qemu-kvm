CFLAGS += -m32
CFLAGS += -D__powerpc__
CFLAGS += -I $(KERNELDIR)/include
# for some reaons binutils hates tlbsx unless we say we're 405  :(
CFLAGS += -Wa,-mregnames,-m405

%.bin: %.o
	$(OBJCOPY) -O binary $^ $@

testobjs := \
	io.bin \
	spin.bin \
	sprg.bin \
	44x/tlbsx.bin \
	44x/tlbwe_16KB.bin \
	44x/tlbwe_hole.bin \
	44x/tlbwe.bin

tests := $(addprefix test/powerpc/, $(testobjs))

all: kvmtrace kvmctl $(tests)

kvmctl_objs = main-ppc.o iotable.o ../libkvm/libkvm.a

arch_clean:
	rm -f $(tests)
