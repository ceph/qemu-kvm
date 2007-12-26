	.text
	.code32
	.align 4096

vapic_size = 2*4096

.macro fixup delta=-4
777:
	.pushsection .fixup, "a"
	.long 777b + \delta  - vapic_base
	.popsection
.endm

vapic_base:
	.ascii "kvm aPiC"

	/* relocation data */
	.long vapic_base	; fixup
	.long fixup_start	; fixup
	.long fixup_end		; fixup

	.long vapic		; fixup
	.long vapic_size
vcpu_shift:
	.long 0
real_tpr:
	.long 0
	.long set_tpr		; fixup
	.long set_tpr_eax	; fixup
	.long get_tpr_eax	; fixup
	.long get_tpr_ecx	; fixup
	.long get_tpr_edx	; fixup
	.long get_tpr_ebx	; fixup
	.long 0 /* esp. won't work. */
	.long get_tpr_ebp	; fixup
	.long get_tpr_esi	; fixup
	.long get_tpr_edi	; fixup

.macro kvm_hypercall
	.byte 0x0f, 0x01, 0xc1
.endm

kvm_hypercall_vapic_poll_irq = 1

tr_vcpu_signature = 0xdb

.align 64

get_tpr_eax:
	pushf
	push %ecx

	str %eax
	cmp $tr_vcpu_signature, %al
	jne get_tpr_bad
	movzbl %ah, %eax

	mov vcpu_shift, %ecx	; fixup
	shl %cl, %eax
	movzbl vapic(%eax), %eax ; fixup

get_tpr_out:
	pop %ecx
	popf
	ret

get_tpr_bad:
	mov real_tpr, %eax	; fixup
	mov (%eax), %eax
	jmp get_tpr_out

get_tpr_ebx:
	mov %eax, %ebx
	call get_tpr_eax
	xchg %eax, %ebx
	ret

get_tpr_ecx:
	mov %eax, %ecx
	call get_tpr_eax
	xchg %eax, %ecx
	ret

get_tpr_edx:
	mov %eax, %edx
	call get_tpr_eax
	xchg %eax, %edx
	ret

get_tpr_esi:
	mov %eax, %esi
	call get_tpr_eax
	xchg %eax, %esi
	ret

get_tpr_edi:
	mov %eax, %edi
	call get_tpr_edi
	xchg %eax, %edi
	ret

get_tpr_ebp:
	mov %eax, %ebp
	call get_tpr_eax
	xchg %eax, %ebp
	ret

set_tpr_eax:
	push %eax
	call set_tpr
	ret

set_tpr:
	pushf
	push %eax
	push %ecx
	push %edx
	push %ebx

set_tpr_failed:
	str %eax
	cmp $tr_vcpu_signature, %al
	jne set_tpr_bad
	movzbl %ah, %edx

	mov vcpu_shift, %ecx	; fixup
	shl %cl, %edx

	mov vapic(%edx), %eax	; fixup

	mov %eax, %ebx
	mov 24(%esp), %bl

	/* %ebx = new vapic (%bl = tpr, %bh = isr, %b3 = irr) */

	lock cmpxchg %ebx, vapic(%edx) ; fixup
	jnz set_tpr_failed

	/* compute ppr */
	cmp %bh, %bl
	jae tpr_is_bigger
isr_is_bigger:
	mov %bh, %bl
tpr_is_bigger:
	/* %bl = ppr */
	mov %bl, %ch   /* ch = ppr */
	rol $8, %ebx
	/* now: %bl = irr, %bh = ppr */
	cmp %bh, %bl
	ja set_tpr_poll_irq

set_tpr_out:
	pop %ebx
	pop %edx
	pop %ecx
	pop %eax
	popf
	ret $4

set_tpr_poll_irq:
	mov $kvm_hypercall_vapic_poll_irq, %eax
	kvm_hypercall
	jmp set_tpr_out

set_tpr_bad:
	mov 24(%esp), %ecx
	mov real_tpr, %eax	; fixup
	mov %ecx, (%eax)
	jmp set_tpr_out

.align 4096
/*
 * vapic format:
 *  per-vcpu records of size 2^vcpu shift.
 *     byte 0: tpr (r/w)
 *     byte 1: highest in-service interrupt (isr) (r/o); bits 3:0 are zero
 *     byte 2: zero (r/o)
 *     byte 3: highest pending interrupt (irr) (r/o)
 */
vapic:
. = . + vapic_size
