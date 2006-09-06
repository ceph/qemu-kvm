#ifndef __KVM_MMU_H
#define __KVM_MMU_H

#define PT_PRESENT_MASK (1ULL << 0)
#define PT64_BASE_ADDR_MASK (((1ULL << 52) - 1) & PAGE_MASK)

#endif
