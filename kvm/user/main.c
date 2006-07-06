#include "hvmctl.h"

int main(int ac, char **av)
{
	hvm_context_t hvm;
	void *vm_mem;

	hvm = hvm_init(0, 0);
	hvm_create(hvm, 128 * 1024 * 1024, &vm_mem);
	hvm_show_regs(hvm, 0);
	while (1)
		hvm_run(hvm, 0);
}
