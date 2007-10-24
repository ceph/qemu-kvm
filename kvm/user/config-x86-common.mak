#This is a make file with common rules for both x86 & x86-64

all: kvmctl libkvm.a flatfiles

kvmctl: LDFLAGS += -pthread -lrt

kvmctl: kvmctl.o main.o

libkvm.a: kvmctl.o
	$(AR) rcs $@ $^

balloon_ctl: balloon_ctl.o

flatfiles_tests-common = test/bootstrap test/vmexit.flat test/smp.flat

flatfiles: $(flatfiles_tests-common) $(flatfile_tests))
