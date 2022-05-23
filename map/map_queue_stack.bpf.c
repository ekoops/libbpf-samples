#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[]
SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __type(value, int);
    __uint(max_entries, 5);
} queue SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK);
    __type(value, int);
    __uint(max_entries, 5);
} stack SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_tracepoint(void *ctx) {
    int value;
    int result;

    /* --- QUEUE --- */

    // queue peek
    result = bpf_map_peek_elem(&queue, &value);
    if (result < 0) {
        bpf_printk("failed to peek element from the queue");
        return -1;
    }
    bpf_printk("successfully peeked element from the queue: %d", value);

    // queue pop
    result = bpf_map_pop_elem(&queue, &value);
    if (result < 0) {
        bpf_printk("failed to pop element from the queue");
        return -2;
    }
    bpf_printk("successfully popped element from the queue: %d", value);

    // queue push
    value = 10;
    result = bpf_map_push_elem(&queue, &value, BPF_EXIST);
    if (result < 0) {
        bpf_printk("failed to push element to the queue");
        return -3;
    }
    bpf_printk("successfully pushed %d into the queue", value);

    /* --- STACK --- */

    // stack peek
    result = bpf_map_peek_elem(&stack, &value);
    if (result < 0) {
        bpf_printk("failed to peek element from the stack");
        return -4;
    }
    bpf_printk("successfully peeked element from the stack: %d", value);

    // stack pop
    result = bpf_map_pop_elem(&stack, &value);
    if (result < 0) {
        bpf_printk("failed to pop element from the stack");
        return -5;
    }
    bpf_printk("successfully popped element from the stack: %d", value);

    // stack push
    value = 10;
    result = bpf_map_push_elem(&stack, &value, BPF_EXIST);
    if (result < 0) {
        bpf_printk("failed to push element to the stack");
        return -6;
    }
    bpf_printk("successfully pushed %d into the stack", value);
    return 0;
}
