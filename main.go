package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 trace trace.c

import (
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs traceObjects
	if err := loadTraceObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()
	
	// Attach Tracepoint
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecveTp, nil)
	if err != nil {
		log.Fatalf("Attaching Tracepoint: %s", err)
	}
	defer tp.Close()

	// Attach Raw Tracepoint
	rawtp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name: "sys_enter", 
		Program: objs.HandleExecveRawTpNonCore,
	})
	if err != nil {
		log.Fatalf("Attaching raw Tracepoint: %s", err)
	}
	defer rawtp.Close()

	// Attach kprobe 
	kprobe, err := link.Kprobe("__x64_sys_execve", objs.KprobeExecveNonCore, nil)
	if err != nil {
		log.Fatalf("Attaching kProbe: %v", err)
	}
	defer kprobe.Close()

	// Attach BTF-Enabled tracepoint
	tpbtf, err := link.AttachTracing(link.TracingOptions{
		Program: objs.HandleExecveBtf,
	})
	if err != nil {
		log.Fatalf("Attaching BTF-Enabled Tracepoint: %v", err)
	}
	defer tpbtf.Close()

	// Attach fentry 
	fentry, err := link.AttachTracing(link.TracingOptions{
		Program: objs.FentryExecve,
	})
	if err != nil {
		log.Fatalf("Attaching Fentry: %v", err)
	}
	defer fentry.Close()

	time.Sleep(time.Second * 15)
}
