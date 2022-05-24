#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <stdio.h>
#include "map_queue_stack.skel.h"
#include "common.h"

int main() {
    struct map_queue_stack_bpf *skel;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    /* setting up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* opening eBPF application */
    skel = map_queue_stack_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open BPF skeleton\n");
        return 1;
    }

    /* loading & verifying eBPF programs */
    err = map_queue_stack_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    int result;

    /* --- QUEUE --- */

    // creating eBPF queue using libbpf helper
    int tmp_queue_fd = bpf_map_create(BPF_MAP_TYPE_QUEUE, "tmp_queue",
                                      0, sizeof(int), 5, NULL);
    if (tmp_queue_fd == -1) {
        fprintf(stderr, "failed to create ebpf queue: %s\n", strerror(errno));
        return -1;
    }
    // the just created queue will not be used in the following code, so closing it
    close(tmp_queue_fd);

    // retrieving queue from the eBPF skeleton
    struct bpf_map *queue = skel->maps.queue;

    // filling the queue
    for (int i = 0; i < 5; i++) {
        result = bpf_map__update_elem(queue, NULL, 0, &i, sizeof(int), BPF_ANY);
        if (result < 0) {
            fprintf(stderr, "failed to push element into the queue: %s\n", strerror(errno));
            return -2;
        }
        printf("element %d successfully pushed into the queue\n", i);
    }
    printf("elements successfully pushed into the queue\n");

    /* --- STACK --- */

    // creating eBPF stack using libbpf helper
    int tmp_stack_fd = bpf_map_create(BPF_MAP_TYPE_STACK, "tmp_stack",
                                      0, sizeof(int), 5, NULL);
    if (tmp_stack_fd == -1) {
        fprintf(stderr, "failed to create ebpf stack: %s\n", strerror(errno));
        return -1;
    }
    // the just created stack will not be used in the following code, so closing it
    close(tmp_stack_fd);

    // retrieving stack from the eBPF skeleton
    struct bpf_map *stack = skel->maps.stack;

    // filling the stack
    for (int i = 0; i < 5; i++) {
        result = bpf_map__update_elem(stack, NULL, 0, &i, sizeof(int), BPF_ANY);
        if (result < 0) {
            fprintf(stderr, "failed to push element into the stack: %s\n", strerror(errno));
            return -2;
        }
        printf("element %d successfully pushed into the stack\n", i);
    }
    printf("elements successfully pushed into the stack\n");

    /* attaching tracepoint handler */
    err = map_queue_stack_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("successfully started! Please run `sudo bpftool map dump name <map_name>` to inspect the eBPF maps or "
           "`sudo cat /sys/kernel/debug/tracing/trace_pipe` to inspect the eBPF program output\n");

    for (;;) {
        fprintf(stderr, ".");
        sleep(1);
    }

    cleanup:
    map_queue_stack_bpf__destroy(skel);
    return -err;
    return 0;
}
