#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// the following map is manipulated by the user space code
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 1);
} map_user SEC(".maps");

// the following map is manipulated by the ebpf code
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 1);
} map_kern SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_tracepoint(void *ctx) {
    int result;
    int key = 0;
    int *value = bpf_map_lookup_elem(&map_kern, &key);
    // if the value is not present, add it
    // if the value is present, delete it
    if (!value) {
        bpf_printk("failed to lookup for key(%d) in eBPF map \'map_kern\'. Trying to insert a new value...\n", key);
        int new_value = 5;
        result = bpf_map_update_elem(&map_kern, &key, &new_value, BPF_NOEXIST);
        if (result < 0) {
            bpf_printk("failed to insert new value(%d) for key(%d) in eBPF map \'map_kern\'", new_value, key);
            return -1;
        }
        bpf_printk("inserted new value(%d) for key(%d) in eBPF map \'map_kern\'", new_value, key);
        return 0;
    }
    bpf_printk("retrieved value(%d) for key(%d) in eBPF map \'map_kern\'. Trying to delete it...\n", *value, key);
    result = bpf_map_delete_elem(&map_kern, &key);
    if (result < 0) {
        bpf_printk("failed to delete value for key(%d) in eBPF map \'map_kern\'\n", key);
        return -2;
    }
    bpf_printk("deleted value for key(%d) in eBPF map \'map_kern\'\n", key);
    return 0;
}
