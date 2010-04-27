
.data

.macro str name, value

\name :	.long 1f-2f
2:	.ascii "\value"
1:	
.endm	

TESTDEV_PORT = 0xf1

	str "forward", "forward"
	str "backward", "backward"
		
.text

.global main
main:
	cld
	movl forward, %ecx
	lea  4+forward, %rsi
	movw $TESTDEV_PORT, %dx
	rep outsb

	std
	movl backward, %ecx
	lea 4+backward-1(%rcx), %rsi
	movw $TESTDEV_PORT, %dx
	rep outsb
	
	mov $0, %rsi
	call exit



