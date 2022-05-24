#ifndef MAP_EXAMPLES_COMMON_H
#define MAP_EXAMPLES_COMMON_H

#include <linux/bpf.h>
#include <bpf/libbpf.h>

int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size);

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args);


#endif //MAP_EXAMPLES_COMMON_H
