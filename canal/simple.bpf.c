#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

SEC("tp/syscalls/sys_enter_execve")
int handle_tp(void* ctx) {]

	bpf_printk("Hello BPF\n");

	return 0;
}
