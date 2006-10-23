
CFLAGS = -I ../kernel/include $(autodepend-flags) -g
CXXFLAGS = $(autodepend-flags) 

autodepend-flags = -MMD -MF $(dir $*).$(notdir $*).d

all: kvmctl libkvm.a flatfiles

kvmctl: kvmctl.o main.o

libkvm.a: kvmctl.o
	$(AR) rcs $@ $^

flatfiles: test/simple.flat test/stringio.flat test/memtest1.flat \
	test/irq.flat test/sieve.flat test/bootstrap

%.flat: %.o
	gcc -nostdlib -o $@ -Wl,-T,flat.lds $^

test/bootstrap: test/bootstrap.o
	gcc -nostdlib -o $@ -Wl,-T,bootstrap.lds $^

%.o: %.S
	gcc -c -nostdlib -o $@ $^

test/irq.flat: test/print.o

test/sieve.flat: test/cstart.o test/sieve.o test/print.o test/vm.o

-include .*.d
