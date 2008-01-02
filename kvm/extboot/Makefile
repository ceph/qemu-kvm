OBJCOPY=objcopy

CFLAGS=-Wall -Wstrict-prototypes -Werror -fomit-frame-pointer -fno-builtin \
       -fno-stack-protector

all: extboot.bin

%.o: %.S
	$(CC) $(CFLAGS) -o $@ -c $<

extboot.img: extboot.o
	$(LD) --oformat binary -Ttext 0 -o $@ $<

extboot.bin: extboot.img signrom
	./signrom extboot.img extboot.bin

signrom: signrom.c
	$(CC) -o $@ -g -Wall $^

clean:
	$(RM) *.o *.img *.bin signrom *~
