
LIBDIR := /lib
CFLAGS += -m32
CFLAGS += -D__powerpc__

libkvm-$(ARCH)-objs := libkvm-powerpc.o
