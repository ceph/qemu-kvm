BEGIN { split("INIT_WORK tsc_khz desc_struct ldttss_desc64 desc_ptr " \
	      "hrtimer_add_expires_ns hrtimer_get_expires " \
	      "hrtimer_get_expires_ns hrtimer_start_expires " \
	      "hrtimer_expires_remaining " \
	      "on_each_cpu relay_open request_irq" , compat_apis); }

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

{ sub(/match->dev->msi_enabled/, "kvm_pcidev_msi_enabled(match->dev)") }

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

/^static int (.*_stat_get|lost_records_get)/ {
    $3 = "__" $3
}

/DEFINE_SIMPLE_ATTRIBUTE.*(_stat_get|lost_records_get)/ {
    name = gensub(/,/, "", "g", $2);
    print "MAKE_SIMPLE_ATTRIBUTE_GETTER(" name ")"
}

{ sub(/linux\/mm_types\.h/, "linux/mm.h") }

{ sub(/\<__user\>/, " ") }

/^\t\.name = "kvm"/ { $0 = "\tset_kset_name(\"kvm\")," }

/#include <linux\/compiler.h>/ { $0 = "" }
/#include <linux\/clocksource.h>/ { $0 = "" }
/#include <linux\/types.h>/ { $0 = "#include <asm/types.h>" }

{ sub(/\<hrtimer_init\>/, "hrtimer_init_p") }
{ sub(/\<hrtimer_start\>/, "hrtimer_start_p") }
{ sub(/\<hrtimer_cancel\>/, "hrtimer_cancel_p") }

/case KVM_CAP_SYNC_MMU/ { $0 = "#ifdef CONFIG_MMU_NOTIFIER\n" $0 "\n#endif" }

{
    for (i in compat_apis) {
	ident = compat_apis[i]
	sub("\\<" ident "\\>", "kvm_" ident)
    }
}

/\kvm_.*_fops\.owner = module;/ { $0 = "IF_ANON_INODES_DOES_REFCOUNTS(" $0 ")" }

{ print }

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
