#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "MIT";

SEC("xdp_pass")
int xdp_pass_prog(struct xdp_md* ctx) {
    ////////
    return XDP_PASS;
}