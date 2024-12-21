//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

#define ARGSIZE 256 

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_tp_non_core(struct trace_event_raw_sys_enter *ctx) {
    char *filename = (char *)BPF_PROBE_READ(ctx, args[0]);

    u8 buf[ARGSIZE];
    bpf_probe_read_user_str(buf, sizeof(buf), filename);

    bpf_printk("Tracepoint triggered for execve syscall with parameter filename: %s\n", buf);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_tp(struct trace_event_raw_sys_enter *ctx) {
    char *filename_ptr = (char *)BPF_CORE_READ(ctx, args[0]);

    u8 filename[ARGSIZE];
    bpf_core_read_user_str(&filename, sizeof(filename), filename_ptr);

    bpf_printk("Tracepoint triggered for execve syscall with parameter filename: %s\n", filename);
    return 0;
}

SEC("raw_tracepoint/sys_enter")
int handle_execve_raw_tp_non_core(struct bpf_raw_tracepoint_args *ctx) {
    // There is no method to attach a raw_tp or tp_btf directly to a single syscall... 
    // this is because there are no static defined tracepoints on single syscalls but only on generic sys_enter/sys_exit
    // So we have to filter by syscall ID
    unsigned long id = BPF_PROBE_READ(ctx, args[1]);
    if (id != 59)   // execve sycall ID
	return 0;

    struct pt_regs *regs = (struct pt_regs *)BPF_PROBE_READ(ctx, args[0]);

    const char *filename;
    bpf_probe_read(&filename, sizeof(filename), &regs->di);

    char buf[ARGSIZE];
    bpf_probe_read_user_str(buf, sizeof(buf), filename);

    bpf_printk("Raw tracepoint triggered for execve syscall with parameter filename: %s\n", buf);
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

    struct pt_regs *regs;
    regs = (struct pt_regs *)ctx->args[0];

    char *filename = (char *)PT_REGS_PARM1_CORE(regs);
    char buf[ARGSIZE];
    bpf_core_read_user_str(buf, sizeof(buf), filename);

    bpf_printk("Raw tracepoint triggered for execve syscall with parameter filename: %s\n", buf);
    return 0;
}

SEC("kprobe/__x64_sys_execve")
int kprobe_execve_non_core(struct pt_regs *ctx) {
    // For Kernel version 4.17.0
    //char *filename = (char *)PT_REGS_PARM1(ctx);

    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);

    char *filename;
    bpf_probe_read(&filename, sizeof(filename), &PT_REGS_PARM1(ctx2));

    char buf[ARGSIZE];
    bpf_core_read_user_str(buf, sizeof(buf), filename);

    // Print the flags value
    bpf_printk("Kprobe triggered for execve syscall with parameter filename: %s\n", buf);

    return 0;
}

SEC("kprobe/__x64_sys_execve")
int kprobe_execve(struct pt_regs *ctx) {
    struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx);

    char *filename = (char *)PT_REGS_PARM1_CORE(regs);
    char buf[ARGSIZE];
    bpf_core_read_user_str(buf, sizeof(buf), filename);

    // Print the flags value
    bpf_printk("Kprobe triggered for execve syscall with parameter filename: %s\n", buf);

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

    char *filename = (char *)PT_REGS_PARM1_CORE(regs);
    char buf[ARGSIZE];
    bpf_core_read_user_str(buf, sizeof(buf), filename);

    bpf_printk("BTF-enabled tracepoint triggered for execve syscall with parameter filename: %s\n", buf);
    return 0;
}

SEC("fentry/__x64_sys_execve")
int BPF_PROG(fentry_execve, const struct pt_regs *regs) {
    char *filename = (char *)PT_REGS_PARM1_CORE(regs);
    char buf[ARGSIZE];
    bpf_core_read_user_str(buf, sizeof(buf), filename);

    bpf_printk("Fentry tracepoint triggered for execve syscall with parameter filename: %s\n", buf);
    return 0;
}
