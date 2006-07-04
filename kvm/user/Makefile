
CFLAGS = -I ../kernel/include $(autodepend-flags) 

autodepend-flags = -MMD -MF $(dir $*).$(notdir $*).d

all: hvmctl

hvmctl: hvmctl.o

-include .*.d
