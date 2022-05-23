#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// creating a BTF-defined ebpf map in kernel space
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 1);
} map3 SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_tracepoint(void *ctx) {
    return 0;
}
