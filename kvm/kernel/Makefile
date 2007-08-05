include ../config.mak

KVERREL = $(patsubst /lib/modules/%/build,%,$(KERNELDIR))

DESTDIR=

INSTALLDIR = $(patsubst %/build,%/extra,$(KERNELDIR))
ORIGMODDIR = $(patsubst %/build,%/kernel,$(KERNELDIR))

rpmrelease = devel

LINUX = ../linux-2.6

version = $(shell cd $(LINUX); git describe)

hack = 	mv $1 $1.orig && \
	awk -v version=$(version) -f hack-module.awk $1.orig > $1 && \
	rm $1.orig


all::
	$(MAKE) -C $(KERNELDIR) M=`pwd` "$$@"

sync:
	rsync --exclude='*.mod.c' "$(LINUX)"/drivers/kvm/*.[ch] .
	rsync "$(LINUX)"/include/linux/kvm.h \
	       "$(LINUX)"/include/linux/kvm_para.h \
			include/linux
	$(call hack, kvm_main.c)
	$(call hack, mmu.c)
	$(call hack, vmx.c)
	$(call hack, svm.c)

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

