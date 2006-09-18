
#if PTTYPE == 64
	#define pt_element_t uint64_t
	#define guest_walker guest_walker64
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
	#define guest_walker guest_walker32
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

/*
 * The guest_walker structure emulates the behavior of the hardware page
 * table walker.
 */
struct guest_walker {	
	int level;
	pt_element_t *table;
	pt_element_t inherited_ar;
};

static void FNAME(init_walker)(struct guest_walker *walker,
			       struct kvm_vcpu *vcpu)
{
	hpa_t hpa;
	struct kvm_memory_slot *slot;

	walker->level = vcpu->mmu.root_level;
	slot = gfn_to_memslot(vcpu->kvm, 
			      (vcpu->cr3 & PT64_BASE_ADDR_MASK) >> PAGE_SHIFT);
	/* FIXME: cr3 -> mmio or nowhere? */
	hpa = gpa_to_hpa(slot, vcpu->cr3 & PT64_BASE_ADDR_MASK);
	walker->table = kmap_atomic(pfn_to_page(hpa >> PAGE_SHIFT), KM_USER0);

	ASSERT((!is_long_mode() && is_pae()) ||
	       (vcpu->cr3 & ~(PAGE_MASK | CR3_FLAGS_MASK)) == 0);
		
	walker->table = (pt_element_t *)( (unsigned long)walker->table |
				(vcpu->cr3 & ~(PAGE_MASK | CR3_FLAGS_MASK)) );
	walker->inherited_ar = PT_USER_MASK | PT_WRITABLE_MASK;
}

static void FNAME(release_walker)(struct guest_walker *walker)
{
	kunmap_atomic(walker->table & PAGE_MASK, KM_USER0);
}

static void FNAME(set_pte)(struct kvm_vcpu *vcpu, uint64_t guest_pte,
			   uint64_t *shadow_pte, uint64_t access_bits)
{
	ASSERT(*shadow_pte == 0);
	access_bits &= guest_pte;
	*shadow_pte = (guest_pte & PT_PTE_COPY_MASK);
	set_pte_common(vcpu, shadow_pte, guest_pte & PT_BASE_ADDR_MASK,
		       guest_pte & PT_DIRTY_MASK, access_bits);
}

static void FNAME(set_pde)(struct kvm_vcpu *vcpu, uint64_t guest_pde,
			   uint64_t *shadow_pte, uint64_t access_bits,
			   int index)
{
	gpa_t gaddr;

	ASSERT(*shadow_pte == 0);
	access_bits &= guest_pde;
	gaddr = (guest_pde & PT_DIR_BASE_ADDR_MASK) + PAGE_SIZE * index;
	if (PTTYPE == 32 && is_cpuid_PSE36())
		gaddr |= (guest_pde & PT32_DIR_PSE36_MASK) <<
			(32 - PT32_DIR_PSE36_SHIFT);
	*shadow_pte = (guest_pde & PT_NON_PTE_COPY_MASK) |
		          ((guest_pde & PT_DIR_PAT_MASK) >>
			            (PT_DIR_PAT_SHIFT - PT_PAT_SHIFT));
	set_pte_common(vcpu, shadow_pte, gaddr,
		       guest_pde & PT_DIRTY_MASK, access_bits);
}

static pt_element_t *FNAME(fetch_guest)(struct kvm_vcpu *vcpu,
					struct guest_walker *walker,
					int level,
					gva_t addr)
{

	ASSERT(level > 0  && level <= walker->level);

	for (;;) {
		int index = PT_INDEX(addr, walker->level);
		struct kvm_memory_slot *slot;
		hpa_t paddr;

		ASSERT(((unsigned long)walker->table & PAGE_MASK) ==
		       ((unsigned long)&walker->table[index] & PAGE_MASK));
		if (level == walker->level ||
		    !is_present_pte(walker->table[index]) ||
		    (walker->level == PT_DIRECTORY_LEVEL &&
		     (walker->table[index] & PT_PAGE_SIZE_MASK) &&
		     (PTTYPE == 64 || is_pse())))
			return &walker->table[index];
		if (walker->level != 3 || is_long_mode())
			walker->inherited_ar &= walker->table[index];
		slot = gfn_to_memslot(vcpu->kvm, (walker->table[index] & PT_BASE_ADDR_MASK) >> PAGE_SHIFT);
		/* FIXME: paging on mmio? */
		paddr = gpa_to_hpa(slot, walker->table[index] & PT_BASE_ADDR_MASK);
		kunmap_atomic(walker->table, KM_USER0);
		walker->table = kmap_atomic(pfn_to_page(paddr >> PAGE_SHIFT),
					    KM_USER0);
		--walker->level;
	}
}

static uint64_t *FNAME(fetch)(struct kvm_vcpu *vcpu, gva_t addr,
			      struct guest_walker *walker)
{
	hpa_t shadow_addr;
	int level;
	uint64_t *prev_shadow_ent = NULL;

	shadow_addr = vcpu->mmu.root_hpa;
	level = vcpu->mmu.shadow_root_level;

	for (; ; level--) {
		uint32_t index = SHADOW_PT_INDEX(addr, level);
		uint64_t *shadow_ent = ((uint64_t *)__va(shadow_addr)) + index;
		pt_element_t *guest_ent;

		if (is_present_pte(*shadow_ent) || is_io_pte(*shadow_ent)) {
			if (level == PT_PAGE_TABLE_LEVEL)
				return shadow_ent;
			shadow_addr = *shadow_ent & PT64_BASE_ADDR_MASK;
			prev_shadow_ent = shadow_ent;
			continue;
		}

		if (PTTYPE == 32 && level > PT32_ROOT_LEVEL) {
			ASSERT(level == PT32E_ROOT_LEVEL);
			guest_ent = FNAME(fetch_guest)(vcpu, walker,
						       PT32_ROOT_LEVEL, addr);
		} else
			guest_ent = FNAME(fetch_guest)(vcpu, walker,
						       level, addr);

		if (!is_present_pte(*guest_ent))
			return NULL;

		/* Don't set accessed bit on PAE PDPTRs */
		if (vcpu->mmu.root_level != 3 || walker->level != 3)
			*guest_ent |= PT_ACCESSED_MASK;

		if (level == PT_PAGE_TABLE_LEVEL) {

			if (walker->level == PT_DIRECTORY_LEVEL) {
				if (prev_shadow_ent)
					*prev_shadow_ent |= PT_SHADOW_PS_MARK;
				FNAME(set_pde)(vcpu, *guest_ent, shadow_ent,
					       walker->inherited_ar,
				          PT_INDEX(addr, PT_PAGE_TABLE_LEVEL));
			} else {
				ASSERT(walker->level == PT_PAGE_TABLE_LEVEL);
				FNAME(set_pte)(vcpu, *guest_ent, shadow_ent, walker->inherited_ar);
			}
			return shadow_ent;
		}

		shadow_addr = kvm_mmu_alloc_page(vcpu);
		if (!VALID_PAGE(shadow_addr))
			return ERR_PTR(-ENOMEM);
		if (!is_long_mode() && level == 3)
			*shadow_ent = shadow_addr |
				(*guest_ent & (PT_PRESENT_MASK | PT_PWT_MASK | PT_PCD_MASK));
		else {
			*shadow_ent = shadow_addr |
				(*guest_ent & PT_NON_PTE_COPY_MASK);
			*shadow_ent |= (PT_WRITABLE_MASK | PT_USER_MASK);
		}
		prev_shadow_ent = shadow_ent;
	}
}

static int FNAME(fix_write_pf)(struct kvm_vcpu *vcpu,
			       uint64_t *shadow_ent,
			       struct guest_walker *walker,
			       gva_t addr,
			       int user)
{
	pt_element_t *guest_ent;
	int writable_shadow;
	gfn_t gfn;

	if (is_writeble_pte(*shadow_ent))
		return 0;

	writable_shadow = *shadow_ent & PT_SHADOW_WRITABLE_MASK;
	if (user) {
		if (!(*shadow_ent & PT_SHADOW_USER_MASK) || !writable_shadow)
			return 0;
		ASSERT(*shadow_ent & PT_USER_MASK);
	} else
		if (!writable_shadow) {
			if (is_write_protection())
				return 0;
			*shadow_ent &= ~PT_USER_MASK;
		}

	guest_ent = FNAME(fetch_guest)(vcpu, walker, PT_PAGE_TABLE_LEVEL, addr);

	if (!is_present_pte(*guest_ent)) {
		*shadow_ent = 0;
		return 0;
	}

	gfn = (*guest_ent & PT64_BASE_ADDR_MASK) >> PAGE_SHIFT;
	mark_page_dirty(vcpu->kvm, gfn);
	*shadow_ent |= PT_WRITABLE_MASK;
	*guest_ent |= PT_DIRTY_MASK;

	return 1;
}

static int FNAME(page_fault)(struct kvm_vcpu *vcpu, gva_t addr,
			       uint32_t error_code)
{
	int write_fault = error_code & PFERR_WRITE_MASK;
	int pte_present = error_code & PFERR_PRESENT_MASK;
	int user_fault = error_code & PFERR_USER_MASK;
	struct guest_walker walker;
	uint64_t *shadow_pte;
	int fixed;

	for (;;) {
		FNAME(init_walker)(&walker, vcpu);
		shadow_pte = FNAME(fetch)(vcpu, addr, &walker);
		if (IS_ERR(shadow_pte)) {  /* must be -ENOMEM */
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

	if (write_fault)
		fixed = FNAME(fix_write_pf)(vcpu, shadow_pte, &walker, addr,
					    user_fault);
	else
		fixed = fix_read_pf(shadow_pte);

	FNAME(release_walker)(&walker);

	if (is_io_pte(*shadow_pte)) {
		if (may_access(*shadow_pte, write_fault, user_fault))
			return 1;
		pgprintk("%s: io work, no access\n", __FUNCTION__);
		inject_page_fault(vcpu, addr,
				  error_code | PFERR_PRESENT_MASK);
		return 0;
	}

	if (pte_present && !fixed) {
		inject_page_fault(vcpu, addr, error_code);
		return 0;
	}

	++kvm_stat.pf_fixed;

	return 0;	
}

static u64 FNAME(fetch_pte)(struct kvm_vcpu *vcpu, gva_t vaddr)
{
	struct guest_walker walker;
	pt_element_t guest_pte;

	FNAME(init_walker)(&walker, vcpu);
	guest_pte = *FNAME(fetch_guest)(vcpu, &walker, PT_PAGE_TABLE_LEVEL, vaddr);

	if (is_present_pte(guest_pte) && walker.level == PT_DIRECTORY_LEVEL) {
		gpa_t gaddr;

		ASSERT((guest_pte & PT_PAGE_SIZE_MASK));

		gaddr = (guest_pte & PT_DIR_BASE_ADDR_MASK) |
			(vaddr & PT_LEVEL_MASK(PT_PAGE_TABLE_LEVEL));
		ASSERT(PTTYPE == 64 || is_pse());

                if (PTTYPE == 32 && is_cpuid_PSE36())
			gaddr |= (guest_pte & PT32_DIR_PSE36_MASK) <<
				(32 - PT32_DIR_PSE36_SHIFT);

		guest_pte &= ~(PT_PAGE_SIZE_MASK | PT_BASE_ADDR_MASK);
		guest_pte |= gaddr;
	}
	FNAME(release_walker)(&walker);
	return guest_pte;
}

#undef pt_element_t
#undef guest_walker
#undef FNAME
#undef PT_BASE_ADDR_MASK
#undef PT_INDEX
#undef SHADOW_PT_INDEX
#undef PT_LEVEL_MASK
#undef PT_PTE_COPY_MASK
#undef PT_NON_PTE_COPY_MASK
#undef PT_DIR_BASE_ADDR_MASK
