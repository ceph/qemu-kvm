
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

/^static void __vmx_load_host_state/ {
    vmx_load_host_state = 1
}

/vmcs_readl\(HOST_GS_BASE\)/ &&  vmx_load_host_state {
    $0 = "\t\twrmsrl(MSR_GS_BASE, gsbase);";
    vmx_load_host_state = 0
}

/atomic_inc\(&kvm->mm->mm_count\);/ { $0 = "mmget(&kvm->mm->mm_count);" }

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

{ sub(/\<tsc_khz\>/, "kvm_tsc_khz") }

{ sub(/\<desc_struct\>/, "kvm_desc_struct") }
{ sub(/\<ldttss_desc64\>/, "kvm_ldttss_desc64") }
{ sub(/\<desc_ptr\>/, "kvm_desc_ptr") }
{ sub(/\<__user\>/, " ") }

/^\t\.name = "kvm"/ { $0 = "\tset_kset_name(\"kvm\")," }

/#include <linux\/compiler.h>/ { $0 = "" }
/#include <linux\/clocksource.h>/ { $0 = "" }

{ sub(/hrtimer_init/, "hrtimer_init_p") }
{ sub(/hrtimer_start/, "hrtimer_start_p") }
{ sub(/hrtimer_cancel/, "hrtimer_cancel_p") }

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

/\tkvm_init_debug/ {
    print "\thrtimer_kallsyms_resolve();"
}
/apic->timer.dev.function =/ {
    print "\thrtimer_data_pointer(&apic->timer.dev);"
}
/pt->timer.function =/ {
    print "\thrtimer_data_pointer(&pt->timer);"
}
