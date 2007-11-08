
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
CFLAGS += -I ../libkvm

LDFLAGS += $(CFLAGS) -L ../libkvm

CXXFLAGS = $(autodepend-flags)

autodepend-flags = -MMD -MF $(dir $*).$(notdir $*).d

kvmctl: LDFLAGS += -pthread -lrt

kvmctl: $(kvmctl_objs)
	$(CC) $(LDFLAGS) $^ -o $@

%.flat: %.o
	$(CC) $(CFLAGS) -nostdlib -o $@ -Wl,-T,flat.lds $^

%.o: %.S
	$(CC) $(CFLAGS) -c -nostdlib -o $@ $^

-include .*.d

clean: arch_clean
	$(RM) kvmctl *.o *.a .*.d
