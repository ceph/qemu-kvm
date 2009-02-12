include ../config.mak
include config.kbuild

ARCH_DIR = $(if $(filter $(ARCH),x86_64 i386),x86,$(ARCH))
ARCH_CONFIG := $(shell echo $(ARCH_DIR) | tr '[:lower:]' '[:upper:]')
# NONARCH_CONFIG used for unifdef, and only cover X86 and IA64 now
NONARCH_CONFIG = $(filter-out $(ARCH_CONFIG),X86 IA64)

KVERREL = $(patsubst /lib/modules/%/build,%,$(KERNELDIR))

DESTDIR=

MAKEFILE_PRE = $(ARCH_DIR)/Makefile.pre

INSTALLDIR = $(patsubst %/build,%/extra,$(KERNELDIR))
ORIGMODDIR = $(patsubst %/build,%/kernel,$(KERNELDIR))

rpmrelease = devel

LINUX = ../linux-2.6

version = $(shell cd $(LINUX); git describe)

_hack = mv $1 $1.orig && \
	gawk -v version=$(version) -f $(ARCH_DIR)/hack-module.awk $1.orig \
	    | sed '/\#include/! s/\blapic\b/l_apic/g' > $1 && rm $1.orig

unifdef = mv $1 $1.orig && cat unifdef.h $1.orig > $1 && rm $1.orig

hack = $(call _hack,$T/$(strip $1))

hack-files-x86 = kvm_main.c mmu.c vmx.c svm.c x86.c irq.h lapic.c i8254.c kvm_trace.c
hack-files-ia64 = kvm_main.c kvm_fw.c kvm_lib.c

hack-files = $(hack-files-$(ARCH_DIR))

ifeq ($(EXT_CONFIG_KVM_TRACE),y)
module_defines += -DEXT_CONFIG_KVM_TRACE=y
endif

all:: header-link prerequisite
#	include header priority 1) $LINUX 2) $KERNELDIR 3) include-compat
	$(MAKE) -C $(KERNELDIR) M=`pwd` \
		LINUXINCLUDE="-I`pwd`/include -Iinclude \
		$(if $(KERNELSOURCEDIR),-Iinclude2 -I$(KERNELSOURCEDIR)/include) \
		-Iarch/${ARCH_DIR}/include -I`pwd`/include-compat \
		-include include/linux/autoconf.h \
		-include `pwd`/$(ARCH_DIR)/external-module-compat.h $(module_defines)"
		"$$@"

sync: header-sync source-sync header-link

header-link:
	rm -f include/asm include-compat/asm
	ln -sf asm-$(ARCH_DIR) include/asm
	ln -sf asm-$(ARCH_DIR) include-compat/asm

T = $(subst -sync,,$@)-tmp

headers-old = $(LINUX)/./include/asm-$(ARCH_DIR)/kvm*.h
headers-new = $(LINUX)/arch/$(ARCH_DIR)/include/asm/./kvm*.h \
	$(LINUX)/arch/$(ARCH_DIR)/include/asm/./vmx*.h \
	$(LINUX)/arch/$(ARCH_DIR)/include/asm/./svm*.h \
	$(LINUX)/arch/$(ARCH_DIR)/include/asm/./virtext*.h

header-sync:
	rm -rf $T
	rsync -R -L \
	     "$(LINUX)"/./include/linux/kvm*.h \
	     $(if $(wildcard $(headers-old)), $(headers-old)) \
             $T/
	$(if $(wildcard $(headers-new)), \
	rsync -R -L \
	     $(wildcard $(headers-new)) \
             $T/include/asm-$(ARCH_DIR)/)

	for i in $$(find $T -name '*.h'); do \
		$(call unifdef,$$i); done
	$(call hack, include/linux/kvm.h)
	$(call hack, include/asm-$(ARCH_DIR)/kvm.h)
	set -e && for i in $$(find $T -type f -printf '%P '); \
		do mkdir -p $$(dirname $$i); cmp -s $$i $T/$$i || cp $T/$$i $$i; done
	rm -rf $T

source-sync:
	rm -rf $T
	rsync --exclude='*.mod.c' -R \
	     "$(LINUX)"/arch/$(ARCH_DIR)/kvm/./*.[cSh] \
	     "$(LINUX)"/virt/kvm/./*.[cSh] \
	     $T/

	for i in $$(find $T -name '*.c'); do \
		$(call unifdef,$$i); done

	for i in $(hack-files); \
		do $(call hack, $$i); done

	for i in $$(find $T -type f -printf '%P '); \
		do cmp -s $(ARCH_DIR)/$$i $T/$$i || cp $T/$$i $(ARCH_DIR)/$$i; done
	rm -rf $T

include $(MAKEFILE_PRE)

install:
	mkdir -p $(DESTDIR)/$(INSTALLDIR)
	cp $(ARCH_DIR)/*.ko $(DESTDIR)/$(INSTALLDIR)
	for i in $(ORIGMODDIR)/drivers/kvm/*.ko \
		 $(ORIGMODDIR)/arch/$(ARCH_DIR)/kvm/*.ko; do \
		if [ -f "$$i" ]; then mv "$$i" "$$i.orig"; fi; \
	done
	/sbin/depmod -a $(DEPMOD_VERSION)

tmpspec = .tmp.kvm-kmod.spec

rpm-topdir := $$(pwd)/../rpmtop

RPMDIR = $(rpm-topdir)/RPMS

rpm:	all
	mkdir -p $(rpm-topdir)/BUILD $(RPMDIR)/$$(uname -i)
	sed 's/^Release:.*/Release: $(rpmrelease)/; s/^%define kverrel.*/%define kverrel $(KVERREL)/' \
	     kvm-kmod.spec > $(tmpspec)
	rpmbuild --define="kverrel $(KVERREL)" \
		 --define="objdir $$(pwd)/$(ARCH_DIR)" \
		 --define="_rpmdir $(RPMDIR)" \
		 --define="_topdir $(rpm-topdir)" \
		-bb $(tmpspec)

clean:
	$(MAKE) -C $(KERNELDIR) M=`pwd` $@
