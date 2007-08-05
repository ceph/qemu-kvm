include ../config.mak

KVERREL = $(patsubst /lib/modules/%/build,%,$(KERNELDIR))

DESTDIR=

INSTALLDIR = $(patsubst %/build,%/extra,$(KERNELDIR))
ORIGMODDIR = $(patsubst %/build,%/kernel,$(KERNELDIR))

rpmrelease = devel

LINUX = ../linux-2.6

version = $(shell cd $(LINUX); git describe)

all::
	$(MAKE) -C $(KERNELDIR) M=`pwd` "$$@"

sync:
	rsync --exclude='*.mod.c' "$(LINUX)"/drivers/kvm/*.[ch] .
	rsync "$(LINUX)"/include/linux/kvm.h \
	       "$(LINUX)"/include/linux/kvm_para.h \
			include/linux
	mv kvm_main.c kvm_main.c.orig
	awk -v version=$(version) \
		-f hack-module.awk kvm_main.c.orig > kvm_main.c
	rm kvm_main.c.orig
	mv mmu.c mmu.c.orig
	awk -f hack-module.awk mmu.c.orig > mmu.c
	rm mmu.c.orig
	mv vmx.c vmx.c.orig
	awk -f hack-module.awk vmx.c.orig > vmx.c
	rm vmx.c.orig
	mv svm.c svm.c.orig
	awk -f hack-module.awk svm.c.orig > svm.c
	rm svm.c.orig

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

