#include <linux/hvm.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

void hvm_create(int fd, unsigned long memory)
{
	int r;
	struct hvm_create create = {
		.memory_size = memory,
	};

	r = ioctl(fd, HVM_CREATE, &create);
	if (r == -1) {
		printf("hvm_create: %m\n");
		exit(1);
	}
}

int main(int ac, char **av)
{
	int fd;

	fd = open("/dev/hvm", O_RDWR);
	if (fd == -1) {
		printf("open: %m\n");
		exit(1);
	}
	hvm_create(fd, 128 * 1024 * 1024);
}
