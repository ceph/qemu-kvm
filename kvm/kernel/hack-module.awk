
/^int kvm_init\(/ { anon_inodes = 1 }

/return 0;/ && anon_inodes {
    print "\tr = kvm_init_anon_inodes();";
    print "\tif (r) {";
    print "\t\t__free_page(bad_page);";
    print "\t\tgoto out;";
    print "\t}";
    print "\tpreempt_notifier_sys_init();";
    printf("\tprintk(\"loaded kvm module (%s)\\n\");\n", version);
    anon_inodes = 0
}

/^void kvm_exit/ { anon_inodes_exit = 1 }

/\}/ && anon_inodes_exit {
    print "\tkvm_exit_anon_inodes();";
    print "\tpreempt_notifier_sys_exit();";
    anon_inodes_exit = 0
}

/MODULE_AUTHOR/ {
    printf("MODULE_INFO(version, \"%s\");\n", version)
}

/^static void vmx_load_host_state/ {
    vmx_load_host_state = 1
}

/vmcs_readl\(HOST_GS_BASE\)/ &&  vmx_load_host_state {
    $0 = "\t\twrmsrl(MSR_GS_BASE, gsbase);";
    vmx_load_host_state = 0
}

/atomic_inc\(&kvm->mm->mm_count\);/ { $0 = "//" $0 }

/^\t\.fault = / {
    fcn = gensub(/,/, "", "g", $3)
    $0 = "\t.VMA_OPS_FAULT(fault) = VMA_OPS_FAULT_FUNC(" fcn "),"
}

/^static int .*_stat_get/ {
    $3 = "__" $3
}

/DEFINE_SIMPLE_ATTRIBUTE.*_stat_get/ {
    name = gensub(/,/, "", "g", $2);
    print "MAKE_SIMPLE_ATTRIBUTE_GETTER(" name ")"
}

{ sub(/linux\/mm_types\.h/, "linux/mm.h") }

{ sub(/tsc_khz/, "kvm_tsc_khz") }

/^\t\.name = "kvm"/ { $0 = "\tset_kset_name(\"kvm\")," }

{ print }

/kvm_x86_ops->run/ {
    print "\tspecial_reload_dr7();"
}

/unsigned long flags;/ &&  vmx_load_host_state {
    print "\tunsigned long gsbase;"
}

/local_irq_save/ &&  vmx_load_host_state {
    print "\t\tgsbase = vmcs_readl(HOST_GS_BASE);"
}
