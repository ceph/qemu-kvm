
DESTDIR =

rpmrelease = devel

.PHONY: kernel user qemu clean

all: kernel user qemu

qemu kernel user:
	$(MAKE) -C $@

qemu: user

clean: 
	@for d in kernel user qemu; do 	\
		$(MAKE) -C $$d $@; 	\
	done

bindir = /usr/bin
bin = $(bindir)/kvm
initdir = /etc/init.d
confdir = /etc/kvm
utilsdir = /etc/kvm/utils

install:
	mkdir -p $(DESTDIR)/$(bindir)
	mkdir -p $(DESTDIR)/$(confdir)
	mkdir -p $(DESTDIR)/$(initdir)
	mkdir -p $(DESTDIR)/$(utilsdir)
	cp qemu/x86_64-softmmu/qemu-system-x86_64 $(DESTDIR)/$(bin)
	cp scripts/kvm $(DESTDIR)/$(initdir)/kvm
	cp scripts/qemu-ifup $(DESTDIR)/$(confdir)/qemu-ifup
	cp kvm $(DESTDIR)/$(utilsdir)/kvm

tmpspec = .tmp.kvm.spec

rpm:	user qemu
	mkdir -p BUILD RPMS/$$(uname -i)
	sed 's/^Release:.*/Release: $(rpmrelease)/' kvm.spec > $(tmpspec)
	rpmbuild --define="kverrel $$(uname -r)" \
		 --define="objdir $$(pwd)" \
		 --define="_topdir $$(pwd)" \
		-bb $(tmpspec)
