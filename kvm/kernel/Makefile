KERNELDIR := /lib/modules/`uname -r`/build
all::
	$(MAKE) -C $(KERNELDIR) M=`pwd` "$$@"

rpm:	all
	mkdir -p BUILD RPMS/$$(uname -m)
	rpmbuild --define="kverrel $$(uname -r)" \
		 --define="objdir $$(pwd)" \
		 --define="_topdir $$(pwd)" \
		-bb kmod-kvm.spec
