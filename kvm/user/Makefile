
CFLAGS = -I ../kernel/include $(autodepend-flags) 
CXXFLAGS = $(autodepend-flags) 

autodepend-flags = -MMD -MF $(dir $*).$(notdir $*).d

all: hvmctl libhvm.a

hvmctl: hvmctl.o main.o

libhvm.a: hvmctl.o
	$(AR) rcs $@ $^

-include .*.d
