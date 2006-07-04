
CFLAGS = -I ../kernel/include $(autodepend-flags) 

autodepend-flags = -MMD -MF .$*.d

all: hvmctl

hvmctl: hvmctl.o

-include .*.d
