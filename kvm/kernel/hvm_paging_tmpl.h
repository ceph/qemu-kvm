

#if PTTYPE == 64
	#define pt_element_t uint64_t
	#define guest_walker_s guest_walker64_s
	#define guest_walker_t guest_walker64_t
	#define FNAME(name) paging##64_##name
	#define PT_BASE_ADDR_MASK PT64_BASE_ADDR_MASK
	#define PT_DIR_BASE_ADDR_MASK PT64_DIR_BASE_ADDR_MASK
	#define PT_INDEX(addr, level) PT64_INDEX(addr, level)
	#define SHADOW_PT_INDEX(addr, level) PT64_INDEX(addr, level)
	#define PT_LEVEL_MASK(level) PT64_LEVEL_MASK(level)
	#define PT_PTE_COPY_MASK PT64_PTE_COPY_MASK
	#define PT_NON_PTE_COPY_MASK PT64_NON_PTE_COPY_MASK
#elif PTTYPE == 32
	#define pt_element_t uint32_t
	#define guest_walker_s guest_walker32_s
	#define guest_walker_t guest_walker32_t
	#define FNAME(name) paging##32_##name
	#define PT_BASE_ADDR_MASK PT32_BASE_ADDR_MASK
	#define PT_DIR_BASE_ADDR_MASK PT32_DIR_BASE_ADDR_MASK
	#define PT_INDEX(addr, level) PT32_INDEX(addr, level)
	#define SHADOW_PT_INDEX(addr, level) PT64_INDEX(addr, level)
	#define PT_LEVEL_MASK(level) PT32_LEVEL_MASK(level)
	#define PT_PTE_COPY_MASK PT32_PTE_COPY_MASK
	#define PT_NON_PTE_COPY_MASK PT32_NON_PTE_COPY_MASK
#else
	error
#endif


typedef struct guest_walker_s {	
	int level;
	pt_element_t *table;
} guest_walker_t;


static void FNAME(init_walker)(guest_walker_t *walker,
				  struct hvm_vcpu *vcpu)
{
	walker->level = vcpu->paging_context.root_level;
	walker->table = kmap_atomic(
		pfn_to_page(gaddr_to_paddr(vcpu, vcpu->cr3) >> PAGE_SHIFT),
		KM_USER0);
}


static inline void FNAME(release_walker)(guest_walker_t *walker)
{
	kunmap_atomic(walker->table, KM_USER0);
}


static inline void FNAME(set_pte)(struct hvm_vcpu *vcpu,
			     uint64_t guest_pte,
			     uint64_t *shadow_pte,
			     uint64_t access_bits)
{
	ASSERT(*shadow_pte == 0);
	access_bits &= guest_pte;
	*shadow_pte = (guest_pte & PT_PTE_COPY_MASK);
	set_pte_common(vcpu, shadow_pte, guest_pte & PT_BASE_ADDR_MASK,
			 access_bits);
}


static inline void FNAME(set_pde)(struct hvm_vcpu *vcpu,
			     uint64_t guest_pde,
			     uint64_t *shadow_pte,
			     uint64_t access_bits,
			     int index)
{
	gaddr_t gaddr;
       
	ASSERT(*shadow_pte == 0);
	access_bits &= guest_pde;
	gaddr = (guest_pde & PT_DIR_BASE_ADDR_MASK) + PAGE_SIZE * index;
#if PTTYPE == 32
	if (is_cpuid_PSE36()) {
		gaddr |= (guest_pde & PT32_DIR_PSE36_MASK) << 
			(32 - PT32_DIR_PSE36_SHIFT);
	}
#endif
	*shadow_pte = (guest_pde & PT_NON_PTE_COPY_MASK) |
				((guest_pde & PT_DIR_PAT_MASK) >> 
				 (PT_DIR_PAT_SHIFT - PT_PAT_SHIFT));
	set_pte_common(vcpu, shadow_pte, gaddr, access_bits);
}


static pt_element_t *FNAME(fetch_guest)(struct hvm_vcpu *vcpu,
			       guest_walker_t *walker, 
			       int level,
			       uint64_t addr)
{

	ASSERT(level > 0  && level <= walker->level);

	for (;;) {
		int index = PT_INDEX(addr, walker->level);
		paddr_t paddr;

		if (level == walker->level ||
		    !is_present_pte(walker->table[index]) ||
		    (walker->level == PT_DIRECTORY_LEVEL &&
		    (walker->table[index] & PT_PAGE_SIZE_MASK) 
#if PTTYPE == 32
		     && is_pse()
#endif
		     
		     )) {
			return &walker->table[index];
		}

		paddr = gaddr_to_paddr(vcpu, walker->table[index] & 
				       PT_BASE_ADDR_MASK);
		kunmap_atomic(walker->table, KM_USER0);
		walker->table = kmap_atomic(pfn_to_page(paddr >> PAGE_SHIFT),
					    KM_USER0);
		--walker->level;
	} 
}


static uint64_t *FNAME(fetch)(struct hvm_vcpu *vcpu,
			 uint64_t addr,
			 guest_walker_t *walker,
			 int *enomem)
{
	paddr_t shadow_addr;
	int level;
	uint64_t *priv_shadow_ent = NULL;

	uint64_t access_bits = PT_USER_MASK | PT_WRITABLE_MASK;

	shadow_addr = vcpu->paging_context.root;
	level = vcpu->paging_context.shadow_root_level;

	for (; ; level--) {
		uint32_t index = SHADOW_PT_INDEX(addr, level);
		uint64_t *shadow_ent = ((uint64_t *)__va(shadow_addr)) + index;
		pt_element_t *guest_ent;

		if (is_present_pte(*shadow_ent) || is_io_pte(*shadow_ent)) {
			if (level == PT_PAGE_TABLE_LEVEL) {
				return shadow_ent;
			}
			access_bits &= *shadow_ent >> PT_SHADOW_BITS_OFFSET;
			shadow_addr = *shadow_ent & PT64_BASE_ADDR_MASK;
			continue;
		}

#if PTTYPE == 32
		if (level > PT32_ROOT_LEVEL) {
			ASSERT(level == PT32E_ROOT_LEVEL);
			guest_ent = FNAME(fetch_guest)(vcpu, walker,
						       PT32_ROOT_LEVEL, addr);
		} else {
#endif
			guest_ent = FNAME(fetch_guest)(vcpu, walker, level, addr);
#if PTTYPE == 32
		}
#endif

		if (!is_present_pte(*guest_ent)) {
			*enomem = 0;
			return NULL;
		}

		*guest_ent |= PT_ACCESSED_MASK;

		if (level == PT_PAGE_TABLE_LEVEL) {

			if (walker->level == PT_DIRECTORY_LEVEL) {
				if (priv_shadow_ent) {
					*priv_shadow_ent |= PT_SHADOW_PS_MARK;
				}
				FNAME(set_pde)(vcpu, *guest_ent, shadow_ent, access_bits,
					  PT_INDEX(addr, PT_PAGE_TABLE_LEVEL));
			} else {
				ASSERT(walker->level == PT_PAGE_TABLE_LEVEL);
				FNAME(set_pte)(vcpu, *guest_ent, shadow_ent, access_bits);
			}
			return shadow_ent;
		}

		shadow_addr = hvm_mmu_alloc_page(vcpu);
		if (!VALID_PAGE(shadow_addr)) {
			*enomem = 1;
			return NULL;
		}
#if PTTYPE == 32
		if (level > PT32_ROOT_LEVEL) {
			*shadow_ent = shadow_addr | 
				(*guest_ent & (PT_PRESENT_MASK | PT_PWT_MASK | PT_PCD_MASK));
		} else {
#endif
			*shadow_ent = shadow_addr | 
				(*guest_ent & PT_NON_PTE_COPY_MASK);
			*shadow_ent |= ( PT_WRITABLE_MASK | PT_USER_MASK);

#if PTTYPE == 32			
		}
#endif
		access_bits &= *guest_ent;
		*shadow_ent |= access_bits << PT_SHADOW_BITS_OFFSET;
		priv_shadow_ent = shadow_ent;
	}
}


static inline int FNAME(fix_write_pf)(struct hvm_vcpu *vcpu,
				 uint64_t *shadow_ent,
				 guest_walker_t *walker,
				 uint64_t addr,
				 int user)
{
	pt_element_t *guest_ent;
	int writable_shadow;

	if (is_writeble_pte(*shadow_ent)) {
		return 0;
	}
	writable_shadow = *shadow_ent & PT_SHADOW_WRITABLE_MASK; 
	if (user) {
		if (!(*shadow_ent & PT_SHADOW_USER_MASK) || !writable_shadow) {
			return 0;
		}
		ASSERT(*shadow_ent & PT_USER_MASK);
	} else {
		if (!writable_shadow) {
			if (is_write_protection()) {
				return 0;
			}
			*shadow_ent &= ~PT_USER_MASK;
		}
	}

	guest_ent = FNAME(fetch_guest)(vcpu, walker, PT_PAGE_TABLE_LEVEL, addr);

	if (!is_present_pte(*guest_ent)) {
		*shadow_ent = 0;
		return 0;
	}

	*shadow_ent |= PT_WRITABLE_MASK;
	*guest_ent |= PT_DIRTY_MASK;

	return 1;
}


static int FNAME(page_fault)(struct hvm_vcpu *vcpu, uint64_t addr,
			       uint32_t error_code)
{
	int write_fault = error_code & PFERR_WRITE_MASK;
	int pte_present = error_code & PFERR_PRESENT_MASK;
	int user_fault = error_code & PFERR_USER_MASK;
	guest_walker_t walker;
	uint64_t *shadow_pte;
	int fixed;

	for (;;) {
		int enomem;

		FNAME(init_walker)(&walker, vcpu);
		shadow_pte = FNAME(fetch)(vcpu, addr, &walker, &enomem);
		if (!shadow_pte && enomem) {
			nonpaging_flush(vcpu);
			FNAME(release_walker)(&walker);
			continue;
		}
		break;
	}

	if (!shadow_pte) {
		inject_page_fault(vcpu, addr, error_code);
		FNAME(release_walker)(&walker);
		return 0;
	}

	//hvm_printf(vcpu->hvm, "%s: addr 0x%llx @ 0x%lx\n",
	//	   __FUNCTION__, addr, vmcs_readl(GUEST_RIP));

	if (write_fault) {
		fixed = FNAME(fix_write_pf)(vcpu, shadow_pte, &walker, addr,
				       user_fault);
	} else {
		fixed = fix_read_pf(shadow_pte);
	}

	FNAME(release_walker)(&walker);

	if (is_io_pte(*shadow_pte)) {
		if (access_test(*shadow_pte, write_fault, user_fault)) {
			return 1;
		}
		pgprintk("%s: io work, no access\n", __FUNCTION__);
		inject_page_fault(vcpu, addr,
					error_code | PFERR_PRESENT_MASK);
		return 0;
	}

	if (pte_present && !fixed) {
		inject_page_fault(vcpu, addr, error_code);     
	}

	hvm_stat.pf_fixed += fixed;

	return 0;	
}


static u64 FNAME(fetch_pte)(struct hvm_vcpu *vcpu, unsigned long vaddr)
{
	guest_walker_t walker;
	pt_element_t guest_pte;

	FNAME(init_walker)(&walker, vcpu);
	guest_pte = *FNAME(fetch_guest)(vcpu, &walker, PT_PAGE_TABLE_LEVEL, vaddr);

	if (!is_present_pte(guest_pte)) {
		printk("%s: 0x%lx not present", __FUNCTION__, vaddr);
	}

	if (is_present_pte(guest_pte) &&
	    walker.level == PT_DIRECTORY_LEVEL) {
		gaddr_t gaddr; 

		ASSERT((guest_pte & PT_PAGE_SIZE_MASK));

		gaddr = (guest_pte & PT_DIR_BASE_ADDR_MASK) | 
			(vaddr & PT_LEVEL_MASK(PT_PAGE_TABLE_LEVEL));
#if PTTYPE == 32
		ASSERT(is_pse());

                if (is_cpuid_PSE36()) {
			gaddr |= (guest_pte & PT32_DIR_PSE36_MASK) << 
				(32 - PT32_DIR_PSE36_SHIFT);
		}
#endif
		guest_pte &= ~(PT_PAGE_SIZE_MASK | PT_BASE_ADDR_MASK);
		guest_pte |= gaddr;
	}
	FNAME(release_walker)(&walker);
	return guest_pte;
}



#undef pt_element_t
#undef guest_walker_s
#undef guest_walker_t
#undef FNAME
#undef PT_BASE_ADDR_MASK
#undef PT_INDEX
#undef SHADOW_PT_INDEX
#undef PT_LEVEL_MASK
#undef PT_PTE_COPY_MASK
#undef PT_NON_PTE_COPY_MASK
#undef PT_DIR_BASE_ADDR_MASK

