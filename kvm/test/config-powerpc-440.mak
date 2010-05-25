

# for some reason binutils hates tlbsx unless we say we're 405  :(
CFLAGS += -Wa,-m405 -I lib/powerpc/44x

cflatobjs += \
	lib/powerpc/44x/map.o \
	lib/powerpc/44x/tlbwe.o \
	lib/powerpc/44x/timebase.o

simpletests += \
	powerpc/44x/tlbsx.bin \
	powerpc/44x/tlbwe_16KB.bin \
	powerpc/44x/tlbwe_hole.bin \
	powerpc/44x/tlbwe.bin
