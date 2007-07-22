
/^static __init int kvm_init\(/ { anon_inodes = 1 }

/return 0;/ && anon_inodes {
    print "\tr = kvm_init_anon_inodes();";
    print "\tif (r) {";
    print "\t\t__free_page(bad_page);";
    print "\t\tgoto out;";
    print "\t}";
    anon_inodes = 0
}

/^static __exit void kvm_exit/ { anon_inodes_exit = 1 }

/\}/ && anon_inodes_exit {
    print "\tkvm_exit_anon_inodes();";
    anon_inodes_exit = 0
}

/kmem_cache_create/ { kmem_cache_create = 1 }

/NULL\)/ && kmem_cache_create {
    sub(/NULL\)/, "KMEM_CACHE_CREATE_CTOR_DTOR)");
    kmem_cache_create = 0
}

{ print }
