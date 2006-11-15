KERNELDIR := /lib/modules/`uname -r`/build

rpmrelease = devel

all::
	$(MAKE) -C $(KERNELDIR) M=`pwd` "$$@"

tmpspec = .tmp.kvm-kmod.spec

rpm:	all
	mkdir -p ../BUILD ../RPMS/$$(uname -m)
	sed 's/^Release:.*/Release: $(rpmrelease)/' kvm-kmod.spec > $(tmpspec)
	rpmbuild --define="kverrel $$(uname -r)" \
		 --define="objdir $$(pwd)" \
		 --define="_topdir $$(pwd)/.." \
		-bb $(tmpspec)

clean:
	$(MAKE) -C $(KERNELDIR) M=`pwd` clean
	rm -f Module.symvers