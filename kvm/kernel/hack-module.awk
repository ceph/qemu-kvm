
/^static __init int kvm_init\(/ { anon_inodes = 1 }

/return 0;/ && anon_inodes {
    print "\tr = kvm_init_anon_inodes();";
    print "\tif (r) {";
    print "\t\t__free_page(bad_page);";
    print "\t\tgoto out;";
    print "\t}";
    print "\tpreempt_notifier_sys_init();";
    anon_inodes = 0
}

/^static __exit void kvm_exit/ { anon_inodes_exit = 1 }

/\}/ && anon_inodes_exit {
    print "\tkvm_exit_anon_inodes();";
    print "\tpreempt_notifier_sys_exit();";
    anon_inodes_exit = 0
}

/kmem_cache_create/ { kmem_cache_create = 1 }

/(NULL|0)\);/ && kmem_cache_create {
    sub(/(NULL|0)\)/, "KMEM_CACHE_CREATE_CTOR_DTOR)");
    kmem_cache_create = 0
}

/MODULE_AUTHOR/ {
    printf("MODULE_INFO(version, \"%s\");\n", version)
}

/^static unsigned long vmcs_readl/ {
    in_vmcs_read = 1
}

/ASM_VMX_VMREAD_RDX_RAX/ && in_vmcs_read {
    printf("\tstart_special_insn();\n")
}

/return/ && in_vmcs_read {
    printf("\tend_special_insn();\n");
    in_vmcs_read = 0
}

/^static void vmcs_writel/ {
    in_vmcs_write = 1
}

/ASM_VMX_VMWRITE_RAX_RDX/ && in_vmcs_write {
    printf("\tstart_special_insn();\n")
}

/if/ && in_vmcs_write {
    printf("\tend_special_insn();\n");
    in_vmcs_write = 0
}

/static int vmx_vcpu_run/ {
    vmx_vcpu_run = 1
}

/preempt_enable/ && vmx_vcpu_run {
    print "\tspecial_reload_dr7();";
    vmx_vcpu_run = 0
}

{ print }

/static void vcpu_put|static int vmx_vcpu_run|static struct kvm_vcpu \*vmx_create_vcpu/ {
    in_tricky_func = 1
}

/preempt_disable|get_cpu/ && in_tricky_func {
    printf("\tin_special_section();\n");
    in_tricky_func = 0
}
