# `rootkit`

Developed for Linux kernel version 6.14.0-37-generic on Ubuntu 25.04, on an x86_64 machine.

We'll implement:
- A privilege escalation with an unused signal sent to `kill`
- Hiding file with the `rootkit_` prefix with `getdents64`


## Background

Before Linux kernel 6.9, there was a `sys_call_table` that was indexed to access the relevant handling function for each system call.

```
// Dispatching to relevant function for sys_kill 
sys_call_table[__NR_kill](regs);
```

To hook syscalls, a rootkit developer would therefore need to be intimately aware of how to manipulate this table.

## Kernel Version 6.9+

In version 6.9, the Linux kernel changed to dispath syscalls with a `switch` statement instead of a table.
The syscall table still exists for compatibility, but edits to the table would not change how a syscall is handled.

## Linux Kernel Module (LKM)

LKMs can be used to hook system calls.
To do this, one must first find the address of the syscall they would like to hook.
As kernel versions have progressed, this has become more challenging.

### `kallsyms_lookup_name`

Until version 5.7, LKM authors could simply lookup any symbol's address with `kallsyms_lookup_name`, including syscall handling functions (e.g. `sys_mkdir`).
This made rootkits simple, and was therefore not exported for use by LKMs in 2020.

### `kprobe`

Until version 6.x, LKM authors could trivially sidestep this change by resolving the address of `kallsyms_lookup_name` with `kprobe`.
When registering a probe, one can simply populate the symbol on which to probe, and the address will be resolved.

```C
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

register_kprobe(&kp);
target_addr = kp.addr; // Gets kallsyms_lookup_name
unregister_kprobe(&kp);
```

### Binary Patching

Rootkit developers later simply patched function prologues directly.
Gross!
As one might expect, this was fragile and prone to crashes.  

## eBPF

eBPF is an in-kernel virtual machine.
They are particularly interesting as they do not load a module, a process which is usually used to detect rootkits.
Nonetheless, they can still hook syscalls.

Examples include:
- Triple Cross (2021) used eBPF to hook syscalls.
- Boopkit (2022) implemented covert C2 entirely via eBPF.

## `io_uring`

In Linux 5.1, `io_uring` was introduced to allow I/O operations to be batched, reducing the overhead of repeated syscalls.
This batching of syscalls makes typical syscall-based detection techniques less reliable as they must now support this new approach to performing the same `read`, `write`, ... operations.


