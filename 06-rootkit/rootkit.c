#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/kprobes.h>

typedef u32 (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t kallsyms_lookup_name_fn = NULL;

int init_rootkit(void)
{
    printk("[rootkit] - Hello\n");

    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
    };

    register_kprobe(&kp);
    kallsyms_lookup_name_fn = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);

    printk("[rootkit] kallsyms_lookup_name = %p\n", kallsyms_lookup_name_fn);
    
    return 0;
}

void exit_rootkit(void)
{
    printk("[rootkit] - Bye\n");
}

module_init(init_rootkit);
module_exit(exit_rootkit);
MODULE_LICENSE("GPL");
