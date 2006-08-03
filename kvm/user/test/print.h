#ifndef PRINT_H
#define PRINT_H

.macro PRINT text

.data

333: .asciz "\text\n"

.previous

	push %rax
	lea 333b, %rax
	call print
	pop %rax

.endm

#endif
