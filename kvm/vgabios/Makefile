SHELL = /bin/sh

CC      = gcc
CFLAGS  = -g -O2 -Wall -Wstrict-prototypes
LDFLAGS = 

RELEASE = `pwd | sed "s-.*/--"`
RELDATE = `date '+%d %b %Y'`

all: bios


bios: vgabios.bin vgabios.debug.bin 

clean:
	/bin/rm -f  *.o *.s *.ld86 \
          temp.awk.* vgabios*.orig _vgabios_* core vgabios*.bin $(RELEASE).bin

dist-clean: clean

release: bios
	/bin/rm -f  *.o *.s *.ld86 \
          temp.awk.* vgabios.*.orig _vgabios_.*.c core
	cp vgabios.bin ../$(RELEASE).bin
	cp vgabios.debug.bin ../$(RELEASE).debug.bin
	rm vgabios.bin 
	rm vgabios.debug.bin
	tar czvf ../$(RELEASE).tgz -C .. $(RELEASE)/

vgabios.bin: vgabios.c vgabios.h vgafonts.h vgatables.h vbe.h vbe.c vbetables.h
	gcc -E vgabios.c -DVBE -DVGABIOS_DATE="\"$(RELDATE)\"" > _vgabios_.c
	bcc -o vgabios.s -C-c -D__i86__ -S -0 _vgabios_.c
	sed -e 's/^\.text//' -e 's/^\.data//' vgabios.s > _vgabios_.s
	as86 _vgabios_.s -b vgabios.bin -u -w- -g -0 -j -O -l vgabios.debug.txt
	rm -f _vgabios_.s _vgabios_.c vgabios.s
	ls -l vgabios.bin

vgabios.debug.bin: vgabios.c vgabios.h vgafonts.h vgatables.h vbe.h vbe.c vbetables.h
	gcc -E vgabios.c -DVBE -DDEBUG -DVGABIOS_DATE="\"$(RELDATE)\"" > _vgabios_.c
	bcc -o vgabios.s -C-c -D__i86__ -S -0 _vgabios_.c
	sed -e 's/^\.text//' -e 's/^\.data//' vgabios.s > _vgabios_.s
	as86 _vgabios_.s -b vgabios.debug.bin -u -w- -g -0 -j -O -l vgabios.txt
	rm -f _vgabios_.s _vgabios_.c vgabios.s
	ls -l vgabios.debug.bin
