KERNELDIR := /lib/modules/$(shell uname -r)/build
KVERREL = $(patsubst /lib/modules/%/build,%,$(KERNELDIR))

rpmrelease = devel

all::
	$(MAKE) -C $(KERNELDIR) M=`pwd` "$$@"

tmpspec = .tmp.kvm-kmod.spec
TARGETDIR = $$(pwd)/../../RPMS
rpm:	all
	mkdir -p ../BUILD $(TARGETDIR)/$$(uname -m)
	sed 's/^Release:.*/Release: $(rpmrelease)/' kvm-kmod.spec > $(tmpspec)
	rpmbuild --define="kverrel $(KVERREL)" \
		 --define="objdir $$(pwd)" \
		 --define="_rpmdir $(TARGETDIR)" \
		 --define="_topdir $$(pwd)/.." \
		-bb $(tmpspec)

clean:
	$(MAKE) -C $(KERNELDIR) M=`pwd` $@

svnclean:
	svn st | grep '^\?' | awk '{print $2}' | xargs rm -rf

