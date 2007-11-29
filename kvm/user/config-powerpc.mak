TEST_DIR=test/powerpc
CFLAGS += -m32
CFLAGS += -D__powerpc__
CFLAGS += -I $(KERNELDIR)/include

tests= $(TEST_DIR)/io.S \
	$(TEST_DIR)/spin.S \
	$(TEST_DIR)/sprg.S \
	$(TEST_DIR)/44x/tlbsx.S \
	$(TEST_DIR)/44x/tlbwe_16KB.S \
	$(TEST_DIR)/44x/tlbwe_hole.S \
	$(TEST_DIR)/44x/tlbwe.S

kvmctl_objs = main.o ../libkvm/libkvm.a
