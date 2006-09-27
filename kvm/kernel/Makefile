KERNELDIR := /lib/modules/`uname -r`/build

rpmrelease = devel

all::
	$(MAKE) -C $(KERNELDIR) M=`pwd` "$$@"

tmpspec = .tmp.kmod-kvm.spec

rpm:	all
	mkdir -p BUILD RPMS/$$(uname -m)
	sed 's/^Release:.*/Release: $(rpmrelease)/' kmod-kvm.spec > $(tmpspec)
	rpmbuild --define="kverrel $$(uname -r)" \
		 --define="objdir $$(pwd)" \
		 --define="_topdir $$(pwd)" \
		 --define="svnrev $(svnrev)" \
		-bb $(tmpspec)
