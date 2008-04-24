include ../config.mak

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
	  unifdef -DCONFIG_X86 $1.orig > $1; \
          [ $$? -le 1 ] && rm $1.orig

hack = $(call _hack,$T/$(strip $1))

all::
#	include header priority 1) $LINUX 2) $KERNELDIR 3) include-compat
	$(MAKE) -C $(KERNELDIR) M=`pwd` \
		LINUXINCLUDE="-I`pwd`/include -Iinclude -I`pwd`/include-compat \
		-include include/linux/autoconf.h" \
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
	ln -sf asm-x86 include/asm
	ln -sf asm-x86 include-compat/asm

source-sync:
	rm -rf $T
	rsync --exclude='*.mod.c' -R \
             "$(LINUX)"/arch/x86/kvm/./*.[ch] \
             "$(LINUX)"/virt/kvm/./*.[ch] \
             $T/
	$(call hack, kvm_main.c)
	$(call hack, mmu.c)
	$(call hack, vmx.c)
	$(call hack, svm.c)
	$(call hack, x86.c)
	$(call hack, irq.h)
	for i in $$(find $T -type f -printf '%P '); \
		do cmp -s $$i $T/$$i || cp $T/$$i $$i; done
	rm -rf $T

install:
	mkdir -p $(DESTDIR)/$(INSTALLDIR)
	cp *.ko $(DESTDIR)/$(INSTALLDIR)
	for i in $(ORIGMODDIR)/drivers/kvm/*.ko \
		 $(ORIGMODDIR)/arch/x86/kvm/*.ko; do \
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
