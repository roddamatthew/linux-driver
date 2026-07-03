#pragma once

#include <linux/ftrace.h>

typedef struct ftrace_hook {
    const char* symbol_name;
    unsigned long symbol_addr;
    unsigned long offset_symbol_addr; // Offest for skipping __fentry prologue
    unsigned long hook_addr;
    struct ftrace_ops ops;
};

/* Forward declarations */
unsigned long resolve_sym(const char* sym);
int resolve_hook(ftrace_hook *hook);
static void hook_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *fregs);
int install_hook(ftrace_hook *hook);
void remove_hook(ftrace_hook *hook);