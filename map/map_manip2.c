#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <errno.h>

/*
 * This sample can be compiled using the following command:
 * clang -g -Wall -lelf -lz map_manip2.c libbpf.a -o map_manip2
 *
 * The sample does not use higher level API such as bpf_map__update_elem or bpf_map__lookup_and_delete_elem
 * since the code is user-space only and I don't know how to retrieve the struct bpf_map pointer associated with
 * the user-space created map.
 */

int main() {
    // creating the eBPF map
    int map_fd = bpf_map_create(BPF_MAP_TYPE_HASH,"map",sizeof(int),
                                sizeof(int),3,NULL);
    if (map_fd == -1) {
        fprintf(stderr, "failed to create eBPF map: %s\n", strerror(errno));
        return -1;
    }

    // the following code shows how to populate an eBPF map
    int result;
    for (int i = 0; i < 3; i++) {
        result = bpf_map_update_elem(map_fd, &i, &i, BPF_NOEXIST);
        if (result < 0) {
            fprintf(stderr, "failed to insert value(%d) for key(%d)\n", i, i);
            return -2;
        }
    }
    printf("map populated successfully\n");

    // the following code uses the bpf_map_lookup_and_delete_elem libbpf helper in order to lookup and
    // contextually delete the retrieved entry from an eBPF map
    int key = 1;
    int value;
    result = bpf_map_lookup_and_delete_elem(map_fd, &key, &value);
    if (result < 0) {
        fprintf(stderr, "failed to lookup for key(%d)\n", key);
        return -3;
    } else {
        printf("retrieved value(%d) for key(%d) and removed from the map\n", value, key);
    }


    // the following code uses the bpf_map_get_next_key libbpf helper in order to iterate over the keys of a map
    int lookup_key, next_key;
    lookup_key = -1;
    while (!bpf_map_get_next_key(map_fd, &lookup_key, &next_key)) {
        printf("key: %d\n", next_key);
        lookup_key = next_key;
    }
    return 0;
}
