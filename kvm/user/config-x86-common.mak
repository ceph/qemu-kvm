#This is a make file with common rules for both x86 & x86-64

CFLAGS += -I../include/x86

all: test_cases

cflatobjs += \
	test/lib/x86/io.o \
	test/lib/x86/smp.o

cflatobjs += test/lib/x86/fwcfg.o
cflatobjs += test/lib/x86/apic.o

$(libcflat): LDFLAGS += -nostdlib
$(libcflat): CFLAGS += -ffreestanding -I test/lib

CFLAGS += -m$(bits)

libgcc := $(shell $(CC) -m$(bits) --print-libgcc-file-name)

FLATLIBS = test/lib/libcflat.a $(libgcc)
%.flat: %.o $(FLATLIBS) flat.lds
	$(CC) $(CFLAGS) -nostdlib -o $@ -Wl,-T,flat.lds $^ $(FLATLIBS)

tests-common = $(TEST_DIR)/vmexit.flat $(TEST_DIR)/tsc.flat \
               $(TEST_DIR)/smptest.flat  $(TEST_DIR)/port80.flat \
               $(TEST_DIR)/realmode.flat $(TEST_DIR)/msr.flat

test_cases: $(tests-common) $(tests)

$(TEST_DIR)/%.o: CFLAGS += -std=gnu99 -ffreestanding -I test/lib -I test/lib/x86
 
$(TEST_DIR)/access.flat: $(cstart.o) $(TEST_DIR)/access.o $(TEST_DIR)/print.o
 
$(TEST_DIR)/hypercall.flat: $(cstart.o) $(TEST_DIR)/hypercall.o $(TEST_DIR)/print.o
 
$(TEST_DIR)/sieve.flat: $(cstart.o) $(TEST_DIR)/sieve.o \
		$(TEST_DIR)/print.o $(TEST_DIR)/vm.o
 
$(TEST_DIR)/vmexit.flat: $(cstart.o) $(TEST_DIR)/vmexit.o
 
$(TEST_DIR)/smptest.flat: $(cstart.o) $(TEST_DIR)/smptest.o
 
$(TEST_DIR)/emulator.flat: $(cstart.o) $(TEST_DIR)/emulator.o \
			   $(TEST_DIR)/vm.o $(TEST_DIR)/print.o

$(TEST_DIR)/port80.flat: $(cstart.o) $(TEST_DIR)/port80.o

$(TEST_DIR)/tsc.flat: $(cstart.o) $(TEST_DIR)/tsc.o

$(TEST_DIR)/apic.flat: $(cstart.o) $(TEST_DIR)/apic.o $(TEST_DIR)/vm.o \
		       $(TEST_DIR)/print.o 

$(TEST_DIR)/realmode.flat: $(TEST_DIR)/realmode.o
	$(CC) -m32 -nostdlib -o $@ -Wl,-T,$(TEST_DIR)/realmode.lds $^

$(TEST_DIR)/realmode.o: bits = 32

$(TEST_DIR)/msr.flat: $(cstart.o) $(TEST_DIR)/msr.o

arch_clean:
	$(RM) $(TEST_DIR)/*.o $(TEST_DIR)/*.flat \
	$(TEST_DIR)/.*.d $(TEST_DIR)/lib/.*.d $(TEST_DIR)/lib/*.o

-include $(TEST_DIR)/.*.d test/lib/.*.d test/lib/x86/.*.d
