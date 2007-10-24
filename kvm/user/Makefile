
include config.mak

DESTDIR :=

.PHONY: arch_clean clean

#make sure env CFLAGS variable is not used
CFLAGS =

#include architecure specific make rules
include config-$(ARCH).mak

# cc-option
# Usage: OP_CFLAGS+=$(call cc-option, -falign-functions=0, -malign-functions=0)

cc-option = $(shell if $(CC) $(1) -S -o /dev/null -xc /dev/null \
              > /dev/null 2>&1; then echo "$(1)"; else echo "$(2)"; fi ;)

CFLAGS += $(autodepend-flags) -g -fomit-frame-pointer -Wall
CFLAGS += $(call cc-option, -fno-stack-protector, "")
CFLAGS += $(call cc-option, -fno-stack-protector-all, "")

LDFLAGS += $(CFLAGS)

CXXFLAGS = $(autodepend-flags)

autodepend-flags = -MMD -MF $(dir $*).$(notdir $*).d

kvmctl: LDFLAGS += -pthread -lrt

kvmctl: $(kvmctl_objs)

libkvm.a: $(libkvm_objs)
	$(AR) rcs $@ $^

install:
	install -D kvmctl.h $(DESTDIR)/$(PREFIX)/include/kvmctl.h
	install -D $(KERNELDIR)/include/linux/kvm.h \
		$(DESTDIR)/$(PREFIX)/include/linux/kvm.h
	install -D $(KERNELDIR)/include/linux/kvm_para.h \
		$(DESTDIR)/$(PREFIX)/include/linux/kvm_para.h
	install -D libkvm.a $(DESTDIR)/$(PREFIX)/$(LIBDIR)/libkvm.a

%.flat: %.o
	$(CC) $(CFLAGS) -nostdlib -o $@ -Wl,-T,flat.lds $^

%.o: %.S
	$(CC) $(CFLAGS) -c -nostdlib -o $@ $^

-include .*.d

clean: arch_clean
	$(RM) kvmctl *.o *.a .*.d
