SHELL = /bin/sh

CC      = gcc
CFLAGS  = -g -O2 -Wall -Wstrict-prototypes
LDFLAGS = 

RELEASE = `pwd | sed "s-.*/--"`
RELDATE = `date '+%d %b %Y'`

all: bios


bios: vgabios.bin vgabios.debug.bin vbebios.bin vbebios.debug.bin

clean:
	/bin/rm -f  *.o *.s *.ld86 \
          temp.awk.* vgabios*.orig _vgabios_*.c core vgabios*.bin $(RELEASE).bin

dist-clean: clean

release: bios
	/bin/rm -f  *.o *.s *.ld86 \
          temp.awk.* vgabios.*.orig _vgabios_.*.c core
	cp vgabios.bin ../$(RELEASE).bin
	cp vgabios.debug.bin ../$(RELEASE).debug.bin
	rm vgabios.bin 
	rm vgabios.debug.bin
	tar czvf ../$(RELEASE).tgz -C .. $(RELEASE)/

vgabios.bin: vgabios.o
	ld86 -0 -r -o vgabios vgabios.o
	tools86 vgabios
	dd if=vgabios of=vgabios.bin ibs=32 skip=1 count=1024
	rm -f vgabios _vgabios_.c
	ls -l vgabios.bin

vgabios.o: vgabios.c vgabios.h vgafonts.h vgatables.h
	gcc -E vgabios.c -DVGABIOS_DATE="\"$(RELDATE)\"" | tools86 -E > _vgabios_.c
	/usr/lib/bcc/bcc-cc1 -o vgabios.s -c -D__i86__ -0 _vgabios_.c
	./dataseghack vgabios.s
	# bug : with -j i get 1 byte displacement at the end of bin file !
	#as86 vgabios.s -o vgabios.o -u -w -g -0 -j
	as86 vgabios.s -o vgabios.o -u -w -g -0 


vgabios.debug.bin: vgabios.debug.o
	ld86 -0 -r -o vgabios.debug vgabios.debug.o
	tools86 vgabios.debug
	dd if=vgabios.debug of=vgabios.debug.bin ibs=32 skip=1 count=1024
	rm -f vgabios.debug _vgabios_.debug.c
	ls -l vgabios.debug.bin

vgabios.debug.o: vgabios.c vgabios.h vgafonts.h vgatables.h
	gcc -E vgabios.c -DDEBUG -DVGABIOS_DATE="\"$(RELDATE)\"" | tools86 -E > _vgabios_.debug.c
	/usr/lib/bcc/bcc-cc1 -t -d -o vgabios.debug.s -c -D__i86__ -0 _vgabios_.debug.c
	./dataseghack vgabios.debug.s
	as86 vgabios.debug.s -o vgabios.debug.o -u -w -g -0 

vbebios.bin: vbebios.o
	ld86 -0 -r -o vbebios vbebios.o
	tools86 vbebios
	dd if=vbebios of=vbebios.bin ibs=32 skip=1 count=1024
	rm -f vbebios _vbebios_.c
	ls -l vbebios.bin

vbebios.o: vgabios.c vgabios.h vgafonts.h vgatables.h vbe.h vbe.c vbetables.h
	gcc -E vgabios.c -DVBE -DVGABIOS_DATE="\"$(RELDATE)\"" | tools86 -E > _vbebios_.c
	/usr/lib/bcc/bcc-cc1 -o vbebios.s -c -D__i86__ -0 _vbebios_.c
	./dataseghack vbebios.s
	# bug : with -j i get 1 byte displacement at the end of bin file !
	#as86 vgabios.s -o vgabios.o -u -w -g -0 -j
	as86 vbebios.s -o vbebios.o -u -w -g -0 


vbebios.debug.bin: vbebios.debug.o
	ld86 -0 -r -o vbebios.debug vbebios.debug.o
	tools86 vbebios.debug
	dd if=vbebios.debug of=vbebios.debug.bin ibs=32 skip=1 count=1024
	rm -f vbebios.debug _vbebios_.debug.c
	ls -l vbebios.debug.bin

vbebios.debug.o: vgabios.c vgabios.h vgafonts.h vgatables.h vbe.h vbe.c vbetables.h
	gcc -E vgabios.c -DVBE -DDEBUG -DVGABIOS_DATE="\"$(RELDATE)\"" | tools86 -E > _vbebios_.debug.c
	/usr/lib/bcc/bcc-cc1 -o vbebios.debug.s -c -D__i86__ -0 _vbebios_.debug.c
	./dataseghack vbebios.debug.s
	as86 vbebios.debug.s -o vbebios.debug.o -u -w -g -0 
