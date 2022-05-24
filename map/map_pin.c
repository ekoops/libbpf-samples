#include <bpf/bpf.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <linux/limits.h>
#include "map_pin.skel.h"
#include "../include/common.h"

char *base_pin_path = "/sys/fs/bpf";
char *map_user_name = "map_user";

int main() {
    struct map_pin_bpf *skel;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    /* setting up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* opening BPF application */
    skel = map_pin_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open BPF skeleton\n");
        return 1;
    }

    /* loading & verifying BPF programs */
    err = map_pin_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    // creating an eBPF map using the libbpf bpf_map_create helper
    int map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, map_user_name,
                                sizeof(int), sizeof(int), 1, NULL);
    if (map_fd == -1) {
        fprintf(stderr, "failed to create eBPF map \'%s\': %s\n", map_user_name, strerror(errno));
        return -1;
    }
    printf("created eBPF map \'%s\'\n", map_user_name);

    // inserting an element in the just created eBPF map
    int key = 123;
    int value = 456;
    int result;
    result = bpf_map_update_elem(map_fd, &key, &value, BPF_NOEXIST);
    if (result < 0) {
        fprintf(stderr, "failed to insert value(%d) for key(%d) into eBPF map \'%s\': %s\n",
                value, key, map_user_name, strerror(errno));
        return -2;
    }
    printf("inserted value(%d) for key(%d) into eBPF map \'%s\'\n", value, key, map_user_name);

    char map_user_path[PATH_MAX];
    snprintf(map_user_path, PATH_MAX, "%s/%s", base_pin_path, map_user_name);

    // pinning the eBPF map in the eBPF filesystem
    result = bpf_obj_pin(map_fd, map_user_path);
    if (result < 0) {
        fprintf(stderr, "failed to pin eBPF map \'%s\': %s\n", map_user_name, strerror(errno));
        return -3;
    }
    printf("pinned eBPF map \'%s\'\n", map_user_name);

    /* attaching tracepoint handler */
    err = map_pin_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach BPF skeleton\n");
        goto cleanup;
    }

    char map_kern_path[PATH_MAX];
    char const *map_kern_name = bpf_map__name(skel->maps.map_kern);
    snprintf(map_kern_path, PATH_MAX, "%s/%s", base_pin_path, map_kern_name);
    printf("successfully started! Please run `sudo ls %s` and `sudo ls %s` to see the eBPF maps "
           "pinned into the eBPF filesystem\nPress ENTER to unpin the maps\n", map_user_path, map_kern_path);

    char enter = 0;
    while (enter != '\r' && enter != '\n') { enter = getchar(); }

    // the map created in user space is unpinned using the `unlink` primitive
    result = unlink(map_user_path);
    if (result < 0) {
        fprintf(stderr, "failed to unpin eBPF map \'%s\': %s\n", map_user_name, strerror(errno));
        return -4;
    }
    printf("unpinned eBPF map \'%s\'\n", map_user_name);

    // the map created by libbpf from the eBPF skeleton can be unpinned using the `bpf_map__unpin` helper
    result = bpf_map__unpin(skel->maps.map_kern, NULL);
    if (result < 0) {
        fprintf(stderr, "failed to unpin eBPF map \'%s\': %s\n", map_kern_name, strerror(errno));
        return -5;
    }

    cleanup:
    map_pin_bpf__destroy(skel);
    return -err;
    return 0;
}