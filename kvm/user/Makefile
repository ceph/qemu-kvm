
include config.mak

CFLAGS = -I $(KERNELDIR)/include $(autodepend-flags) -g -fomit-frame-pointer \
	-Wall -m$(bits)
CXXFLAGS = $(autodepend-flags) 

autodepend-flags = -MMD -MF $(dir $*).$(notdir $*).d

DESTDIR = 

ifeq ($(shell uname -m), x86_64)
LIBDIR = /lib64
cstart.o = test/cstart64.o
bits = 64
ldarch = elf64-x86-64
else
LIBDIR = /lib
cstart.o = test/cstart.o
bits = 32
ldarch = elf32-i386
endif

all: kvmctl libkvm.a

kvmctl: kvmctl.o main.o

balloon_ctl: balloon_ctl.o

libkvm.a: kvmctl.o
	$(AR) rcs $@ $^

flatfiles-common = test/simple.flat test/stringio.flat test/memtest1.flat \
	test/bootstrap test/vmexit.flat

flatfiles-32 = 

flatfiles-64 = test/access.flat test/irq.flat test/sieve.flat

flatfiles: $(flatfiles-common) $(flatfiles-$(bits))

install:
	install -D kvmctl.h $(DESTDIR)/$(PREFIX)/include/kvmctl.h
	install -D $(KERNELDIR)/include/linux/kvm.h \
		$(DESTDIR)/$(PREFIX)/include/linux/kvm.h
	install -D libkvm.a $(DESTDIR)/$(PREFIX)/$(LIBDIR)/libkvm.a

%.flat: %.o
	gcc $(CFLAGS) -nostdlib -o $@ -Wl,-T,flat.lds $^

test/bootstrap: test/bootstrap.o
	gcc -nostdlib -o $@ -Wl,-T,bootstrap.lds $^

%.o: %.S
	gcc $(CFLAGS) -c -nostdlib -o $@ $^

test/irq.flat: test/print.o

test/access.flat: $(cstart.o) test/access.o test/printf.o test/print.o

test/sieve.flat: $(cstart.o) test/sieve.o test/print.o test/vm.o

test/vmexit.flat: $(cstart.o) test/vmexit.o test/printf.o

test/test32.flat: test/test32.o

test/%.o: CFLAGS += -std=gnu99 -ffreestanding

-include .*.d

clean:
	$(RM) kvmctl *.o *.a .*.d
	$(RM) test/bootstrap test/*.o test/*.flat test/.*.d
