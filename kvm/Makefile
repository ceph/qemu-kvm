

.PHONY: kernel user qemu

all: kernel user qemu

qemu kernel user:
	$(MAKE) -C $@

qemu: user