//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_tp(struct trace_event_raw_sys_enter *ctx) {
    // Irrelevant operation but here to showcase the CO-RE operation
    unsigned long int id = 0;
    BPF_CORE_READ_INTO(&id, ctx, id);
    if (id != 59)   // execve sycall ID
	return 0;

    bpf_printk("Tracepoint triggered for execve syscall\n");
    return 0;
}

SEC("raw_tracepoint/sys_enter")
int handle_execve_raw_tp(struct bpf_raw_tracepoint_args *ctx) {
    // There is no method to attach a raw_tp or tp_btf directly to a single syscall... 
    // this is because there are no static defined tracepoints on single syscalls but only on generic sys_enter/sys_exit
    // So we have to filter by syscall ID
    unsigned long id = 0;
    BPF_CORE_READ_INTO(&id, ctx, args[1]); // Syscall ID is the second element
    if (id != 59)   // execve sycall ID
	return 0;

    bpf_printk("Raw tracepoint triggered for execve syscall\n");
    return 0;
}

SEC("kprobe/__x64_sys_execve")
int kprobe_execve(struct pt_regs *ctx) {
    unsigned long flags = 0;

    // Directly read the some parameter from pt_regs using CO-RE
    BPF_CORE_READ_INTO(&flags, ctx, dx);

    // Print the flags value
    bpf_printk("Kprobe triggered for execve syscall. Flags: %lu\n", flags);

    return 0;
}

SEC("tp_btf/sys_enter")
int BPF_PROG(handle_execve_btf, struct pt_regs *regs, long id) {
    // There is no method to attach a tp_btf directly to a single syscall... 
    // this is because there are no static defined tracepoints on single syscalls but only on generic sys_enter/sys_exit
    // So we have to filter by syscall ID
    //
    // Syscall ID is the second argument in sys_enter hook (BPF_PROG casts it to provide a more 'natural' way of accessing it)
    if (id != 59)  // execve syscall ID
        return 0; 

    bpf_printk("BTF-enabled tracepoint triggered for execve syscall\n");
    return 0;
}

SEC("fentry/__x64_sys_execve")
int BPF_PROG(fentry_execve, const struct pt_regs *regs) {
    bpf_printk("Fentry triggered for execve syscall\n");
    return 0;
}
