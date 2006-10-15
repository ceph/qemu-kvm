
rpmrelease = devel

.PHONY: kernel user qemu

all: kernel user qemu

qemu kernel user:
	$(MAKE) -C $@

qemu: user

tmpspec = .tmp.kvm.spec

rpm:	user qemu
	mkdir -p BUILD RPMS/$$(uname -i)
	sed 's/^Release:.*/Release: $(rpmrelease)/' kvm.spec > $(tmpspec)
	rpmbuild --define="kverrel $$(uname -r)" \
		 --define="objdir $$(pwd)" \
		 --define="_topdir $$(pwd)" \
		-bb $(tmpspec)
