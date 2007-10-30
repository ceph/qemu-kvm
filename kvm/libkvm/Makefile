include ../config.mak
include config-$(ARCH).mak

# cc-option
# Usage: OP_CFLAGS+=$(call cc-option, -falign-functions=0, -malign-functions=0)
cc-option = $(shell if $(CC) $(1) -S -o /dev/null -xc /dev/null \
              > /dev/null 2>&1; then echo "$(1)"; else echo "$(2)"; fi ;)

CFLAGS += $(autodepend-flags) -g -fomit-frame-pointer -Wall
CFLAGS += $(call cc-option, -fno-stack-protector, "")
CFLAGS += $(call cc-option, -fno-stack-protector-all, "")
CFLAGS += -I $(KERNELDIR)/include

LDFLAGS += $(CFLAGS)

CXXFLAGS = $(autodepend-flags)

autodepend-flags = -MMD -MF $(dir $*).$(notdir $*).d


all: libkvm.a

libkvm.a: libkvm.o
	$(AR) rcs $@ $^

install:
	install -D libkvm.h $(DESTDIR)/$(PREFIX)/include/libkvm.h
	install -D $(KERNELDIR)/include/linux/kvm.h \
		$(DESTDIR)/$(PREFIX)/include/linux/kvm.h
	install -D $(KERNELDIR)/include/linux/kvm_para.h \
		$(DESTDIR)/$(PREFIX)/include/linux/kvm_para.h
	install -D libkvm.a $(DESTDIR)/$(PREFIX)/$(LIBDIR)/libkvm.a

-include .*.d

clean:
	$(RM) *.o *.a .*.d
