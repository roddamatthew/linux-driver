#pragma once

#include <linux/ftrace.h>

typedef struct ftrace_hook {
    const char *name;
    void *function;
    void *original;
    unsigned long address;
    struct ftrace_ops ops;
} ftrace_hook;

/* Forward declarations */
unsigned long resolve_sym(const char* sym);
int resolve_hook(ftrace_hook *hook);
static void hook_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *fregs);
int install_hook(ftrace_hook *hook);
void remove_hook(ftrace_hook *hook);