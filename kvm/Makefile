
include config.mak

DESTDIR=

rpmrelease = devel

.PHONY: kernel user libkvm qemu bios clean

all: $(if $(WANT_MODULE), kernel) user libkvm qemu

kcmd = $(if $(WANT_MODULE),,@\#)

qemu kernel user libkvm:
	$(MAKE) -C $@

qemu: libkvm
user: libkvm

bios:
	$(MAKE) -C $@
	cp bios/BIOS-bochs-latest qemu/pc-bios/bios.bin

bindir = /usr/bin
bin = $(bindir)/kvm
initdir = /etc/init.d
confdir = /etc/kvm
utilsdir = /etc/kvm/utils

install-rpm:
	mkdir -p $(DESTDIR)/$(bindir)
	mkdir -p $(DESTDIR)/$(confdir)
	mkdir -p $(DESTDIR)/$(initdir)
	mkdir -p $(DESTDIR)/$(utilsdir)
	mkdir -p $(DESTDIR)/etc/udev/rules.d
	make -C qemu DESTDIR=$(DESTDIR)/ install
	ln -sf /usr/kvm/bin/qemu-system-x86_64 $(DESTDIR)/$(bin)
	install -m 755 kvm_stat $(DESTDIR)/$(bindir)/kvm_stat
	cp scripts/kvm $(DESTDIR)/$(initdir)/kvm
	cp scripts/qemu-ifup $(DESTDIR)/$(confdir)/qemu-ifup
	install -t $(DESTDIR)/etc/udev/rules.d scripts/*kvm*.rules

install:
	$(kcmd)make -C kernel DESTDIR="$(DESTDIR)" install
	make -C libkvm DESTDIR="$(DESTDIR)" install
	make -C qemu DESTDIR="$(DESTDIR)" install

tmpspec = .tmp.kvm.spec
RPMTOPDIR = $$(pwd)/rpmtop

rpm:	srpm
	rm -rf $(RPMTOPDIR)/BUILD
	mkdir -p $(RPMTOPDIR)/{BUILD,RPMS/$$(uname -i)}
	rpmbuild --rebuild \
		 --define="_topdir $(RPMTOPDIR)" \
		$(RPMTOPDIR)/SRPMS/kvm-0.0-$(rpmrelease).src.rpm

srpm:
	mkdir -p $(RPMTOPDIR)/{SOURCES,SRPMS}
	sed 's/^Release:.*/Release: $(rpmrelease)/' kvm.spec > $(tmpspec)
	tar czf $(RPMTOPDIR)/SOURCES/kvm.tar.gz qemu
	tar czf $(RPMTOPDIR)/SOURCES/user.tar.gz user
	tar czf $(RPMTOPDIR)/SOURCES/libkvm.tar.gz libkvm
	tar czf $(RPMTOPDIR)/SOURCES/kernel.tar.gz kernel
	tar czf $(RPMTOPDIR)/SOURCES/scripts.tar.gz scripts
	cp Makefile configure kvm_stat $(RPMTOPDIR)/SOURCES
	rpmbuild  --define="_topdir $(RPMTOPDIR)" -bs $(tmpspec)
	$(RM) $(tmpspec)

clean:
	for i in $(if $(WANT_MODULE), kernel) user libkvm qemu; do \
		make -C $$i clean; \
	done
	rm -f config.mak user/config.mak
