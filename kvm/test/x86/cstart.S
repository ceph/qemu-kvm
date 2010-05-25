

.bss

.section .init

mb_magic = 0x1BADB002
mb_flags = 0x0

	# multiboot header
	.long mb_magic, mb_flags, 0 - (mb_magic + mb_flags)

.globl start
start:
	call main
	push %eax
	call exit


