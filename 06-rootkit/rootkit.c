#include <linux/module.h>
#include <linux/init.h>

int init_rootkit(void)
{
    printk("[rootkit] - Hello\n");
    return 0;
}

void exit_rootkit(void)
{
    printk("[rootkit] - Bye\n");
}

module_init(init_rootkit);
module_exit(exit_rootkit);
MODULE_LICENCE("GPL");
