#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <canal/rudp.h>

struct bpf_map_def SEC("maps") acknowledged = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int)
    .value_size = sizeof(u32),
    .max_entries = 2,
};

SEC("ingress_controller")
int ingress_controller_prog(struct xdp_md* ctx) {
    int ipsize = 0;
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    struct ethhdr* eth = data;
    struct iphdr* ip;

    ipsize = sizeof(*eth);
    ip = data + ipsize;
    ipsize += sizeof(struct iphdr);

    if (data + ipsize > data_end) return XDP_DROP;
    if (ip->protocol != IPPROTO_UDP) return XDP_DROP;

    // 1. Parse RUDP header

    // 2-1. DROP if ACK and notify to egress controller and user program

    // 2-2. Else, redirect?

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";