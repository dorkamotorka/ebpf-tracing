# eBPF Tracing

It is safe to say that almost all eBPF programs can extract and send kernel event data to user space applications.

However, tracing programs like kprobes, fprobes, and tracepoints are often preferred because they hook onto kernel events with access to rich, actionable data for tasks like performance monitoring or syscall argument tracing.

But their overlapping functionality can make choosing the right one confusing.

This demo repository showcases different ways to implement tracing in the eBPF program. It also provides a CO-RE program version for each type. 

Namely, it covers:

- Regular eBPF Tracepoint
- Raw eBPF Tracepoint
- BTF-enabled Tracepoint
- Kprobe
- FProbe

## Build & Run

You need run the program using:

```
go generate
go build
sudo ./trace
```

**NOTE:** By default non CO-RE programs are attached and ran, but you can change this behaviour by uncommenting the corresponding function in the `trace.c` and attaching it in the `main.go` file.
