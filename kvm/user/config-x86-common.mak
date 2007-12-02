#This is a make file with common rules for both x86 & x86-64

all: kvmctl test_cases

kvmctl_objs= main.o ../libkvm/libkvm.a

balloon_ctl: balloon_ctl.o

tests-common = $(TEST_DIR)/bootstrap \
			$(TEST_DIR)/vmexit.flat \
			$(TEST_DIR)/smp.flat

test_cases: $(tests-common) $(tests)

$(TEST_DIR)/%.o: CFLAGS += -std=gnu99 -ffreestanding -I$(TEST_DIR)/lib
 
$(TEST_DIR)/bootstrap: $(TEST_DIR)/bootstrap.o
	$(CC) -nostdlib -o $@ -Wl,-T,bootstrap.lds $^
 
$(TEST_DIR)/irq.flat: $(TEST_DIR)/print.o
 
$(TEST_DIR)/access.flat: $(cstart.o) $(TEST_DIR)/access.o $(TEST_DIR)/print.o
 
$(TEST_DIR)/hypercall.flat: $(cstart.o) $(TEST_DIR)/hypercall.o $(TEST_DIR)/print.o
 
$(TEST_DIR)/sieve.flat: $(cstart.o) $(TEST_DIR)/sieve.o \
		$(TEST_DIR)/print.o $(TEST_DIR)/vm.o
 
$(TEST_DIR)/vmexit.flat: $(cstart.o) $(TEST_DIR)/vmexit.o
 
$(TEST_DIR)/test32.flat: $(TEST_DIR)/test32.o

$(TEST_DIR)/smp.flat: $(cstart.o) $(TEST_DIR)/smptest.o
 
$(TEST_DIR)/emulator.flat: $(cstart.o) $(TEST_DIR)/vm.o $(TEST_DIR)/print.o

$(TEST_DIR)/libcflat.a: $(TEST_DIR)/lib/exit.o $(TEST_DIR)/lib/printf.o \
	$(TEST_DIR)/lib/smp.o
	ar rcs $@ $^

arch_clean:
	$(RM) $(TEST_DIR)/bootstrap $(TEST_DIR)/*.o $(TEST_DIR)/*.flat \
	$(TEST_DIR)/.*.d $(TEST_DIR)/lib/.*.d $(TEST_DIR)/lib/*.o
