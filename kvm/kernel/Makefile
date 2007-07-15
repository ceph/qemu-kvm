include ../config.mak

KVERREL = $(patsubst /lib/modules/%/build,%,$(KERNELDIR))

DESTDIR=

INSTALLDIR = $(patsubst %/build,%/extra,$(KERNELDIR))
ORIGMODDIR = $(patsubst %/build,%/kernel,$(KERNELDIR))

rpmrelease = devel

LINUX = ../linux-2.6

all::
	$(MAKE) -C $(KERNELDIR) M=`pwd` "$$@"

sync:
	rsync --exclude='*.mod.c' "$(LINUX)"/drivers/kvm/*.[ch] .
	rsync "$(LINUX)"/include/linux/kvm.h \
	       "$(LINUX)"/include/linux/kvm_para.h \
			include/linux
	mv kvm_main.c kvm_main.c.orig
	awk '/^static __init int kvm_init\(/ { anon_inodes = 1 }          \
	     /return 0;/ && anon_inodes {                                 \
			print "\tr = kvm_init_anon_inodes();";            \
			print "\tif (r) {";                               \
			print "\t\t__free_page(bad_page);";               \
			print "\t\tgoto out;";                            \
			print "\t}";                                      \
			anon_inodes = 0                                   \
			}                                                 \
	     /^static __exit void kvm_exit/ { anon_inodes_exit = 1 }      \
	     /\}/ && anon_inodes_exit {                                   \
			print "\tkvm_exit_anon_inodes();";                \
			anon_inodes_exit = 0                              \
			}                                                 \
	     { print }                                                    \
	     ' kvm_main.c.orig > kvm_main.c
	rm kvm_main.c.orig

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

