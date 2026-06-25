# `rootkit`

Developed for Linux kernel version 6.14.0-37-generic on Ubuntu 25.04, on an x86_64 machine.

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
