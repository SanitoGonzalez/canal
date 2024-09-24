#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// #include <canal/rudp.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} egress_event SEC(".maps");


SEC("ingress")
int ingress_prog(struct xdp_md* ctx) {
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


SEC("egress")
int egress_prog(struct bpf_perf_event_data* ctx) {
    char msg[] = "Hello from egress";
    bpf_perf_event_output(ctx, &egress_event, BPF_F_CURRENT_CPU, msg, sizeof(msg));

    // 1. If RELIABLE packet, buffer to map and start retransmission. Else, pass

    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";