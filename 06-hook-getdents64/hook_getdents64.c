#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/ftrace.h>

#include "hook_getdents64.h"

static struct ftrace_ops ops = {
    .func = hook_getdents64,
    .flags = FTRACE_OPS_FL_SAVE_REGS,
};

static void hook_getdents64(unsigned long ip,
                            unsigned long parent_ip,
                            struct ftrace_ops *ops,
                            struct ftrace_regs *fregs
                        )
{
    struct pt_regs *regs;
    regs = ftrace_get_regs(fregs);
    if (!regs) {
        pr_info("[rootkit] error - couldn't access regs in hook_getdents64\n");
        return;
    }
    
    pr_info("[rootkit] getdents64(fd=%lu, dirent=%px, count=%lu)\n",
            regs->di,
            (void __user *)regs->si,
            regs->dx);
}


int init_rootkit(void)
{
    pr_info("[rootkit] - Hello\n");

    // Register a hook
    ftrace_set_filter(&ops, "__x64_sys_getdents64", 0, 0);
    register_ftrace_function(&ops);
    
    return 0;
}

void exit_rootkit(void)
{
    // Unregister hook
    unregister_ftrace_function(&ops);
    ftrace_set_filter(&ops, NULL, 0, 1);

    pr_info("[rootkit] - Bye\n");
}

module_init(init_rootkit);
module_exit(exit_rootkit);
MODULE_LICENSE("GPL");
