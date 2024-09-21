#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual MIT/GSL";

SEC("xdp")
int xdp_prog(struct xdp_md* ctx) {
    return XDP_PASS;
}