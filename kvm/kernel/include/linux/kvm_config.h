#ifndef __KVM_CONFIG__H_
#define __KVM_CONFIG__H_

/* defining KVM_NR_INTERRUPTS, the number of interrupts kvm supports (irq lines)
 *     and the number of array entries needed (according to type) to hold a 
 *     bitmap for that number of interrupts.
 */
#define KVM_NR_INTERRUPTS 256
#define KVM_IRQ_BITMAP_SIZE_BYTES    (KVM_NR_INTERRUPTS + 7 / 8)
#define KVM_IRQ_BITMAP_SIZE(type)    (KVM_IRQ_BITMAP_SIZE_BYTES / sizeof(type))
#endif
