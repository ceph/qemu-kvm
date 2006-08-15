
CFLAGS = -I ../kernel/include $(autodepend-flags) -g
CXXFLAGS = $(autodepend-flags) 

autodepend-flags = -MMD -MF $(dir $*).$(notdir $*).d

all: hvmctl libhvm.a flatfiles

hvmctl: hvmctl.o main.o

libhvm.a: hvmctl.o
	$(AR) rcs $@ $^

flatfiles: test/simple.flat test/stringio.flat test/memtest1.flat \
	test/irq.flat test/sieve.flat

%.flat: %.o
	gcc -nostdlib -o $@ -Wl,-T,flat.lds $^

%.o: %.S
	gcc -c -nostdlib -o $@ $^

test/irq.flat: test/print.o

test/sieve.flat: test/cstart.o test/sieve.o test/print.o

-include .*.d
