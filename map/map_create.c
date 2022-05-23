#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <stdio.h>
#include "map_create.skel.h"
#include "common.h"

int main() {
    struct map_create_bpf *skel;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    /* setting up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* opening eBPF application */
    skel = map_create_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open BPF skeleton\n");
        return 1;
    }

    // creating eBPF map using bpf call
    union bpf_attr map1 = {
            .map_type = BPF_MAP_TYPE_HASH,
            .key_size = sizeof(int),
            .value_size = sizeof(int),
            .max_entries = 100,
            .map_flags = BPF_F_NO_PREALLOC,
    };
    int map1_fd = bpf(BPF_MAP_CREATE, &map1, sizeof(map1));
    if (map1_fd == -1) {
        fprintf(stderr, "failed to create map1 (syscall): %s\n", strerror(errno));
        return -1;
    }
    printf("map1 (syscall) file descriptor: %d\n", map1_fd);

    // creating eBPF map using libbpf helper
    int map2_fd = bpf_create_map(
            BPF_MAP_TYPE_HASH,
            sizeof(int),
            sizeof(int),
            100,
            BPF_F_NO_PREALLOC
    );
    if (map2_fd == -1) {
        fprintf(stderr, "failed to create map2 (libbpf): %s\n", strerror(errno));
        return -2;
    }
    printf("map2 (libbpf) file descriptor: %d\n", map2_fd);

    /* loading & verifying BPF programs */
    err = map_create_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* attaching tracepoint handler */
    err = map_create_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("successfully started! Please run `sudo bpftool map show` to see the created ebpf maps\n");

    for (;;) {
        fprintf(stderr, ".");
        sleep(1);
    }

    cleanup:
    map_create_bpf__destroy(skel);
    return -err;
    return 0;
}
