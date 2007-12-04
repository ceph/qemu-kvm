include ../config.mak

KVERREL = $(patsubst /lib/modules/%/build,%,$(KERNELDIR))

DESTDIR=

INSTALLDIR = $(patsubst %/build,%/extra,$(KERNELDIR))
ORIGMODDIR = $(patsubst %/build,%/kernel,$(KERNELDIR))

rpmrelease = devel

LINUX = ../linux-2.6

version = $(shell cd $(LINUX); git describe)

_hack = mv $1 $1.orig && \
	awk -v version=$(version) -f hack-module.awk $1.orig \
	    | sed 's/\blapic\b/l_apic/g' > $1 && rm $1.orig

_unifdef = mv $1 $1.orig && \
	  unifdef -DCONFIG_X86 $1.orig > $1; \
          (( $$? <= 1 )) && rm $1.orig

hack = $(call _hack,tmp/$(strip $1))
unifdef = $(call _unifdef,tmp/$(strip $1))

all::
	$(MAKE) -C $(KERNELDIR) M=`pwd` "$$@"

sync:
	rm -rf tmp
	rsync --exclude='*.mod.c' -R \
             "$(LINUX)"/drivers/kvm/./*.[ch] \
	     "$(LINUX)"/./include/linux/kvm*.h \
	     "$(LINUX)"/./include/asm-x86/kvm*.h \
             tmp/
	ln -sf asm-x86 include/asm

	$(call unifdef, include/linux/kvm.h)
	$(call unifdef, include/linux/kvm_para.h)
	$(call unifdef, include/asm-x86/kvm.h)
	$(call unifdef, include/asm-x86/kvm_para.h)
	$(call hack, kvm_main.c)
	$(call hack, mmu.c)
	$(call hack, vmx.c)
	$(call hack, svm.c)
	$(call hack, x86.c)
	@$(foreach i, $(shell find tmp -type f -printf '%P\n'), \
		if ! cmp -s $i tmp/$i; then cp tmp/$i $i; fi && ) :

install:
	mkdir -p $(DESTDIR)/$(INSTALLDIR)
	cp *.ko $(DESTDIR)/$(INSTALLDIR)
	for i in $(ORIGMODDIR)/drivers/kvm/*.ko; do \
		if [ -f "$$i" ]; then mv "$$i" "$$i.orig"; fi; \
	done
	/sbin/depmod -a

tmpspec = .tmp.kvm-kmod.spec
RPMDIR = $$(pwd)/../RPMS
rpm:	all
	mkdir -p ../BUILD $(RPMDIR)/$$(uname -i)
	sed 's/^Release:.*/Release: $(rpmrelease)/; s/^%define kverrel.*/%define kverrel $(KVERREL)/' \
	     kvm-kmod.spec > $(tmpspec)
	rpmbuild --define="kverrel $(KVERREL)" \
		 --define="objdir $$(pwd)" \
		 --define="_rpmdir $(RPMDIR)" \
		 --define="_topdir $$(pwd)/.." \
		-bb $(tmpspec)

clean:
	$(MAKE) -C $(KERNELDIR) M=`pwd` $@

svnclean:
	svn st | grep '^\?' | awk '{print $2}' | xargs rm -rf

