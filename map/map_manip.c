#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <stdio.h>
#include "map_manip.skel.h"
#include "common.h"

int main() {
    struct map_manip_bpf *skel;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    /* setting up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* opening BPF application */
    skel = map_manip_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open BPF skeleton\n");
        return 1;
    }

    /* loading & verifying BPF programs */
    err = map_manip_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    // retrieving the ebpf map file descriptor
    int map_fd = bpf_map__fd(skel->maps.map_user);
    if (map_fd < 0) {
        printf("failed to retrieve eBPF map file descriptor\n");
        return -1;
    }
    int key = 0;
    int value;
    int result = bpf_map_lookup_elem(map_fd, &key, &value);
    // if the value is not present, add it
    // if the value is present, delete it
    if (result < 0) {
        printf("failed to lookup for key(%d) in map_user. Trying to insert a new value...\n", key);
        value = 5;
        result = bpf_map_update_elem(map_fd, &key, &value, BPF_NOEXIST);
        if (result < 0) {
            fprintf(stderr,"failed to insert new value(%d) for key(%d) in map_user\n", value, key);
            return -2;
        }
        printf("inserted new value(%d) for key(%d) in map_user\n", value, key);
    }
    else {
        printf("retrieved value(%d) for key(%d) in map_user. Trying to delete it...\n", value, key);
        result = bpf_map_delete_elem(map_fd, &key);
        if (result < 0) {
            fprintf(stderr,"failed to delete value for key(%d) in map_user\n", key);
            return -3;
        }
        printf("deleted value for key(%d) in map_user\n", key);
    }

    /* attaching tracepoint handler */
    err = map_manip_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("successfully started! Please run `sudo bpftool map dump <map_name>` to inspect the eBPF maps or "
    "`sudo cat /sys/kernel/debug/tracing/trace_pipe` to inspect the eBPF program output\n");

    for (;;) {
        fprintf(stderr, ".");
        sleep(1);
    }

    cleanup:
    map_manip_bpf__destroy(skel);
    return -err;
    return 0;
}
