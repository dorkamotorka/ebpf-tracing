//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_tp(struct trace_event_raw_sys_enter *ctx) {
    bpf_printk("Normal tracepoint triggered for execve syscall\n");
    return 0;
}

SEC("raw_tracepoint/sys_enter")
int handle_execve_raw_tp(struct bpf_raw_tracepoint_args *ctx) {
    // There is no method to attach a raw_tp or tp_btf directly to a single syscall... 
    // this is because there are no static defined tracepoints on single syscalls but only on generic sys_enter/sys_exit
    // So we have to filter by syscall ID
    unsigned long syscall_id = ctx->args[1];
    if (syscall_id != 59)   // execve sycall ID
	return 0;

    bpf_printk("Raw tracepoint triggered for execve syscall\n");
    return 0;
}

SEC("tp_btf/sys_enter")
int BPF_PROG(handle_execve_btf, struct pt_regs *regs, long id) {
    // Syscall ID is passed as the second argument to the BPF_PROG
    if (id != 59)  // execve syscall ID
        return 0; 

    bpf_printk("BTF-enabled tracepoint triggered for execve syscall\n");
    return 0;
}

SEC("kprobe/__x64_sys_execve")
int kprobe_execve(struct pt_regs *ctx) {
    bpf_printk("Kprobe triggered for execve syscall\n");
    return 0;
}

SEC("fentry/__x64_sys_execve")
int BPF_PROG(fentry_execve, const struct pt_regs *regs) {
    bpf_printk("Fentry triggered for execve syscall\n");
    return 0;
}
