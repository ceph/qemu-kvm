BEGIN { split("INIT_WORK on_each_cpu smp_call_function " \
	      "request_irq", compat_apis); }

/MODULE_AUTHOR/ {
    printf("MODULE_INFO(version, \"%s\");\n", version)
}

{ sub(/..\/..\/..\/lib\/vsprintf\.c/, "vsprintf.c") }
{ sub(/..\/..\/..\/lib\/ctype\.c/, "ctype.c") }
/#undef CONFIG_MODULES/ { $0 = "" }

{
    for (i in compat_apis) {
	ident = compat_apis[i]
	sub("\\<" ident "\\>", "kvm_" ident)
    }
}

/#include <linux\/compiler.h>/ { $0 = "" }

{ sub(/linux\/mm_types\.h/, "linux/mm.h") }

{ sub(/\<__user\>/, " ") }

{ print }
