#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>

u64 target_addr;

int init_rootkit(void)
{
    printk("[rootkit] - Hello\n");

    target_addr = kallsyms_lookup_name(SYSCALL_NAME("sys_mkdir"));
    printk("[rootkit] - target_addr = 0x%llX", target_addr);

    return 0;
}

void exit_rootkit(void)
{
    printk("[rootkit] - Bye\n");
}

module_init(init_rootkit);
module_exit(exit_rootkit);
MODULE_LICENSE("GPL");
