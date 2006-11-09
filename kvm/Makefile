
include config.mak

DESTDIR=

rpmrelease = devel

.PHONY: kernel user qemu

all: $(if $(WANT_MODULE), kernel) user qemu

qemu kernel user:
	$(MAKE) -C $@

qemu: user

install:
	make -C user DESTDIR="$(DESTDIR)" install
	make -C qemu DESTDIR="$(DESTDIR)" install

tmpspec = .tmp.kvm.spec

rpm:	user qemu
	mkdir -p BUILD RPMS/$$(uname -i)
	sed 's/^Release:.*/Release: $(rpmrelease)/' kvm.spec > $(tmpspec)
	rpmbuild --define="kverrel $$(uname -r)" \
		 --define="objdir $$(pwd)" \
		 --define="_topdir $$(pwd)" \
		-bb $(tmpspec)
