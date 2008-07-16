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
	.long up_set_tpr	; fixup
	.long up_set_tpr_eax	; fixup
	.long up_get_tpr_eax	; fixup
	.long up_get_tpr_ecx	; fixup
	.long up_get_tpr_edx	; fixup
	.long up_get_tpr_ebx	; fixup
	.long 0 /* esp. won't work. */
	.long up_get_tpr_ebp	; fixup
	.long up_get_tpr_esi	; fixup
	.long up_get_tpr_edi	; fixup
	.long up_get_tpr_stack  ; fixup
	.long mp_set_tpr	; fixup
	.long mp_set_tpr_eax	; fixup
	.long mp_get_tpr_eax	; fixup
	.long mp_get_tpr_ecx	; fixup
	.long mp_get_tpr_edx	; fixup
	.long mp_get_tpr_ebx	; fixup
	.long 0 /* esp. won't work. */
	.long mp_get_tpr_ebp	; fixup
	.long mp_get_tpr_esi	; fixup
	.long mp_get_tpr_edi	; fixup
	.long mp_get_tpr_stack  ; fixup

.macro kvm_hypercall
	.byte 0x0f, 0x01, 0xc1
.endm

kvm_hypercall_vapic_poll_irq = 1

tr_vcpu_signature = 0xdb

.align 64

mp_get_tpr_eax:
	pushf
	cli
	push %ecx

	str %eax
	cmp $tr_vcpu_signature, %al
	jne mp_get_tpr_bad
	movzbl %ah, %eax

	mov vcpu_shift, %ecx	; fixup
	shl %cl, %eax
	movzbl vapic(%eax), %eax ; fixup

mp_get_tpr_out:
	pop %ecx
	popf
	ret

mp_get_tpr_bad:
	mov real_tpr, %eax	; fixup
	mov (%eax), %eax
	jmp mp_get_tpr_out

mp_get_tpr_ebx:
	mov %eax, %ebx
	call mp_get_tpr_eax
	xchg %eax, %ebx
	ret

mp_get_tpr_ecx:
	mov %eax, %ecx
	call mp_get_tpr_eax
	xchg %eax, %ecx
	ret

mp_get_tpr_edx:
	mov %eax, %edx
	call mp_get_tpr_eax
	xchg %eax, %edx
	ret

mp_get_tpr_esi:
	mov %eax, %esi
	call mp_get_tpr_eax
	xchg %eax, %esi
	ret

mp_get_tpr_edi:
	mov %eax, %edi
	call mp_get_tpr_edi
	xchg %eax, %edi
	ret

mp_get_tpr_ebp:
	mov %eax, %ebp
	call mp_get_tpr_eax
	xchg %eax, %ebp
	ret

mp_get_tpr_stack:
	call mp_get_tpr_eax
	xchg %eax, 4(%esp)
	ret

mp_set_tpr_eax:
	push %eax
	call mp_set_tpr
	ret

mp_set_tpr:
	pushf
	push %eax
	push %ecx
	push %edx
	push %ebx
	cli

mp_set_tpr_failed:
	str %eax
	cmp $tr_vcpu_signature, %al
	jne mp_set_tpr_bad
	movzbl %ah, %edx

	mov vcpu_shift, %ecx	; fixup
	shl %cl, %edx

	mov vapic(%edx), %eax	; fixup

	mov %eax, %ebx
	mov 24(%esp), %bl

	/* %ebx = new vapic (%bl = tpr, %bh = isr, %b3 = irr) */

	lock cmpxchg %ebx, vapic(%edx) ; fixup
	jnz mp_set_tpr_failed

	/* compute ppr */
	cmp %bh, %bl
	jae mp_tpr_is_bigger
mp_isr_is_bigger:
	mov %bh, %bl
mp_tpr_is_bigger:
	/* %bl = ppr */
	mov %bl, %ch   /* ch = ppr */
	rol $8, %ebx
	/* now: %bl = irr, %bh = ppr */
	cmp %bh, %bl
	ja mp_set_tpr_poll_irq

mp_set_tpr_out:
	pop %ebx
	pop %edx
	pop %ecx
	pop %eax
	popf
	ret $4

mp_set_tpr_poll_irq:
	mov $kvm_hypercall_vapic_poll_irq, %eax
	kvm_hypercall
	jmp mp_set_tpr_out

mp_set_tpr_bad:
	mov 24(%esp), %ecx
	mov real_tpr, %eax	; fixup
	mov %ecx, (%eax)
	jmp mp_set_tpr_out

up_get_tpr_eax:
	movzbl vapic, %eax ; fixup
	ret

up_get_tpr_ebx:
	movzbl vapic, %ebx ; fixup
	ret

up_get_tpr_ecx:
	movzbl vapic, %ecx ; fixup
	ret

up_get_tpr_edx:
	movzbl vapic, %edx ; fixup
	ret

up_get_tpr_esi:
	movzbl vapic, %esi ; fixup
	ret

up_get_tpr_edi:
	movzbl vapic, %edi ; fixup
	ret

up_get_tpr_ebp:
	movzbl vapic, %ebp ; fixup
	ret

up_get_tpr_stack:
	movzbl vapic, %eax ; fixup
	xchg %eax, 4(%esp)
	ret

up_set_tpr_eax:
	push %eax
	call up_set_tpr
	ret

up_set_tpr:
	pushf
	push %eax
	push %ecx
	push %ebx

up_set_tpr_failed:
	mov vapic, %eax	; fixup

	mov %eax, %ebx
	mov 20(%esp), %bl

	/* %ebx = new vapic (%bl = tpr, %bh = isr, %b3 = irr) */

	lock cmpxchg %ebx, vapic ; fixup
	jnz up_set_tpr_failed

	/* compute ppr */
	cmp %bh, %bl
	jae up_tpr_is_bigger
up_isr_is_bigger:
	mov %bh, %bl
up_tpr_is_bigger:
	/* %bl = ppr */
	mov %bl, %ch   /* ch = ppr */
	rol $8, %ebx
	/* now: %bl = irr, %bh = ppr */
	cmp %bh, %bl
	ja up_set_tpr_poll_irq

up_set_tpr_out:
	pop %ebx
	pop %ecx
	pop %eax
	popf
	ret $4

up_set_tpr_poll_irq:
	mov $kvm_hypercall_vapic_poll_irq, %eax
	kvm_hypercall
	jmp up_set_tpr_out

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
