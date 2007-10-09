
include config.mak

DESTDIR :=

#make sure env CFLAGS variable is not used
CFLAGS =

#include architecure specific make rules
include config-$(ARCH).mak

# cc-option
# Usage: OP_CFLAGS+=$(call cc-option, -falign-functions=0, -malign-functions=0)

cc-option = $(shell if $(CC) $(1) -S -o /dev/null -xc /dev/null \
              > /dev/null 2>&1; then echo "$(1)"; else echo "$(2)"; fi ;)

CFLAGS += -I $(KERNELDIR)/include $(autodepend-flags) -g -fomit-frame-pointer \
	-Wall
CFLAGS += $(call cc-option, -fno-stack-protector, "")
CFLAGS += $(call cc-option, -fno-stack-protector-all, "")

LDFLAGS += $(CFLAGS)

CXXFLAGS = $(autodepend-flags) 

autodepend-flags = -MMD -MF $(dir $*).$(notdir $*).d

all: kvmctl libkvm.a flatfiles

kvmctl: LDFLAGS += -pthread -lrt

kvmctl: kvmctl.o main.o

balloon_ctl: balloon_ctl.o

libkvm.a: kvmctl.o
	$(AR) rcs $@ $^

flatfiles-common = test/bootstrap test/vmexit.flat test/smp.flat

flatfiles: $(flatfiles-common) $(flatfiles)

install:
	install -D kvmctl.h $(DESTDIR)/$(PREFIX)/include/kvmctl.h
	install -D $(KERNELDIR)/include/linux/kvm.h \
		$(DESTDIR)/$(PREFIX)/include/linux/kvm.h
	install -D $(KERNELDIR)/include/linux/kvm_para.h \
		$(DESTDIR)/$(PREFIX)/include/linux/kvm_para.h
	install -D libkvm.a $(DESTDIR)/$(PREFIX)/$(LIBDIR)/libkvm.a

%.flat: %.o
	$(CC) $(CFLAGS) -nostdlib -o $@ -Wl,-T,flat.lds $^

test/bootstrap: test/bootstrap.o
	$(CC) -nostdlib -o $@ -Wl,-T,bootstrap.lds $^

%.o: %.S
	$(CC) $(CFLAGS) -c -nostdlib -o $@ $^

test/irq.flat: test/print.o

test/access.flat: $(cstart.o) test/access.o test/printf.o test/print.o \
	test/smp.o

test/sieve.flat: $(cstart.o) test/sieve.o test/print.o test/vm.o

test/vmexit.flat: $(cstart.o) test/vmexit.o test/printf.o test/smp.o

test/test32.flat: test/test32.o

test/smp.flat: $(cstart.o) test/smp.o test/printf.o test/smptest.o

test/%.o: CFLAGS += -std=gnu99 -ffreestanding

-include .*.d

clean:
	$(RM) kvmctl *.o *.a .*.d
	$(RM) test/bootstrap test/*.o test/*.flat test/.*.d
