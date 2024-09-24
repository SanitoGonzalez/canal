#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "controller.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args) {
    return vfprintf(stderr, format, args);
}

int main(int argc, char** argv)
{
    struct controller_bpf* skel;
    int err;

    libbpf_set_print(libbpf_print_fn);

    skel = controller_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return EXIT_FAILURE;
    }

    err = controller_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    err = controller_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    for (;;) {
        fprintf(stderr, ".");
        sleep(1);
    }    

cleanup:
    controller_bpf__destroy(skel);
    return -err;
}