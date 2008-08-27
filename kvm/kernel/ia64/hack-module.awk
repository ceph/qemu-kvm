BEGIN { split("INIT_WORK on_each_cpu smp_call_function" , compat_apis); }

/MODULE_AUTHOR/ {
    printf("MODULE_INFO(version, \"%s\");\n", version)
}

{
    for (i in compat_apis) {
	ident = compat_apis[i]
	sub("\\<" ident "\\>", "kvm_" ident)
    }
}

{ print }
