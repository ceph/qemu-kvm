include ../config.mak

ARCH_DIR = $(if $(filter $(ARCH),x86_64 i386),x86,$(ARCH))
ARCH_CONFIG := $(shell echo $(ARCH_DIR) | tr '[:lower:]' '[:upper:]')

KVERREL = $(patsubst /lib/modules/%/build,%,$(KERNELDIR))

DESTDIR=

INSTALLDIR = $(patsubst %/build,%/extra,$(KERNELDIR))
ORIGMODDIR = $(patsubst %/build,%/kernel,$(KERNELDIR))

rpmrelease = devel

LINUX = ../linux-2.6

version = $(shell cd $(LINUX); git describe)

_hack = mv $1 $1.orig && \
	gawk -v version=$(version) -f hack-module.awk $1.orig \
	    | sed '/\#include/! s/\blapic\b/l_apic/g' > $1 && rm $1.orig

unifdef = mv $1 $1.orig && \
	  unifdef -DCONFIG_$(ARCH_CONFIG) $1.orig > $1; \
          [ $$? -le 1 ] && rm $1.orig

hack = $(call _hack,$T/$(strip $1))

hack-files-x86 = kvm_main.c mmu.c vmx.c svm.c x86.c irq.h lapic.c i8254.c

hack-files = $(hack-files-$(ARCH_DIR))

all::
#	include header priority 1) $LINUX 2) $KERNELDIR 3) include-compat
	$(MAKE) -C $(KERNELDIR) M=`pwd` \
		LINUXINCLUDE="-I`pwd`/include -Iinclude -I`pwd`/include-compat \
		-include include/linux/autoconf.h \
		-include `pwd`/$(ARCH_DIR)/external-module-compat.h"
		"$$@"

sync: header-sync source-sync

T = $(subst -sync,,$@)-tmp

header-sync:
	rm -rf $T
	rsync -R \
	     "$(LINUX)"/./include/linux/kvm*.h \
	     "$(LINUX)"/./include/asm-*/kvm*.h \
             $T/

	set -e && for i in $(find $T -name '*.h'); do \
		$(call unifdef,$$i); done
	$(call hack, include/linux/kvm.h)
	set -e && for i in $$(find $T -type f -printf '%P '); \
		do mkdir -p $$(dirname $$i); cmp -s $$i $T/$$i || cp $T/$$i $$i; done
	rm -rf $T

	rm -f include/asm
	ln -sf asm-$(ARCH_DIR) include/asm
	ln -sf asm-$(ARCH_DIR) include-compat/asm

source-sync:
	rm -rf $T
	rsync --exclude='*.mod.c' -R \
	     "$(LINUX)"/arch/$(ARCH_DIR)/kvm/./*.[ch] \
	     "$(LINUX)"/virt/kvm/./*.[ch] \
	     $T/

	for i in $(hack-files); \
		do $(call hack, $$i); done

	for i in $$(find $T -type f -printf '%P '); \
		do cmp -s $$i $T/$$i || cp $T/$$i $$i; done
	rm -rf $T

install:
	mkdir -p $(DESTDIR)/$(INSTALLDIR)
	cp *.ko $(DESTDIR)/$(INSTALLDIR)
	for i in $(ORIGMODDIR)/drivers/kvm/*.ko \
		 $(ORIGMODDIR)/arch/$(ARCH_DIR)/kvm/*.ko; do \
		if [ -f "$$i" ]; then mv "$$i" "$$i.orig"; fi; \
	done
	/sbin/depmod -a

tmpspec = .tmp.kvm-kmod.spec

rpm-topdir := $$(pwd)/../rpmtop

RPMDIR = $(rpm-topdir)/RPMS

rpm:	all
	mkdir -p $(rpm-topdir)/BUILD $(RPMDIR)/$$(uname -i)
	sed 's/^Release:.*/Release: $(rpmrelease)/; s/^%define kverrel.*/%define kverrel $(KVERREL)/' \
	     kvm-kmod.spec > $(tmpspec)
	rpmbuild --define="kverrel $(KVERREL)" \
		 --define="objdir $$(pwd)" \
		 --define="_rpmdir $(RPMDIR)" \
		 --define="_topdir $(rpm-topdir)" \
		-bb $(tmpspec)

clean:
	$(MAKE) -C $(KERNELDIR) M=`pwd` $@
