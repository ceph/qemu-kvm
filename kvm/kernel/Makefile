include ../config.mak

KVERREL = $(patsubst /lib/modules/%/build,%,$(KERNELDIR))

DESTDIR=

INSTALLDIR = $(patsubst %/build,%/extra,$(KERNELDIR))

rpmrelease = devel

LINUX = ../linux-2.6

all::
	$(MAKE) -C $(KERNELDIR) M=`pwd` "$$@"

sync:
	cp -p "$(LINUX)"/drivers/kvm/*.[ch] .
	cp -p "$(LINUX)"/include/linux/kvm.h \
	       "$(LINUX)"/include/linux/kvm_para.h \
			include/linux
	sed -i 's/f_path\./f_/' kvm_main.c
	sed -i 's/f_mnt/f_vfsmnt/' kvm_main.c
	touch -r "$(LINUX)"/drivers/kvm/kvm_main.c kvm_main.c

install:
	mkdir -p $(DESTDIR)/$(INSTALLDIR)
	cp *.ko $(DESTDIR)/$(INSTALLDIR)
	/sbin/depmod -a

tmpspec = .tmp.kvm-kmod.spec
RPMDIR = $$(pwd)/../RPMS
rpm:	all
	mkdir -p ../BUILD $(RPMDIR)/$$(uname -m)
	sed 's/^Release:.*/Release: $(rpmrelease)/' kvm-kmod.spec > $(tmpspec)
	rpmbuild --define="kverrel $(KVERREL)" \
		 --define="objdir $$(pwd)" \
		 --define="_rpmdir $(RPMDIR)" \
		 --define="_topdir $$(pwd)/.." \
		-bb $(tmpspec)

clean:
	$(MAKE) -C $(KERNELDIR) M=`pwd` $@

svnclean:
	svn st | grep '^\?' | awk '{print $2}' | xargs rm -rf

