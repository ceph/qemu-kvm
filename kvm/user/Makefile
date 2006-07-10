
CFLAGS = -I ../kernel/include $(autodepend-flags) -g
CXXFLAGS = $(autodepend-flags) 

autodepend-flags = -MMD -MF $(dir $*).$(notdir $*).d

all: hvmctl libhvm.a flatfiles

hvmctl: hvmctl.o main.o

libhvm.a: hvmctl.o
	$(AR) rcs $@ $^

flatfiles: test/simple.flat test/stringio.flat test/memtest1.flat \
	test/irq.flat

%.flat: %.S
	gcc -nostdlib -o $@ -Wl,-T,flat.lds $^

-include .*.d
