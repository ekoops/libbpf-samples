/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED! */
#ifndef __MAP_PIN_BPF_SKEL_H__
#define __MAP_PIN_BPF_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

struct map_pin_bpf {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *map_kern;
		struct bpf_map *rodata;
	} maps;
	struct {
		struct bpf_program *handle_tracepoint;
	} progs;
	struct {
		struct bpf_link *handle_tracepoint;
	} links;
	struct map_pin_bpf__rodata {
	} *rodata;

#ifdef __cplusplus
	static inline struct map_pin_bpf *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct map_pin_bpf *open_and_load();
	static inline int load(struct map_pin_bpf *skel);
	static inline int attach(struct map_pin_bpf *skel);
	static inline void detach(struct map_pin_bpf *skel);
	static inline void destroy(struct map_pin_bpf *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
map_pin_bpf__destroy(struct map_pin_bpf *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
map_pin_bpf__create_skeleton(struct map_pin_bpf *obj);

static inline struct map_pin_bpf *
map_pin_bpf__open_opts(const struct bpf_object_open_opts *opts)
{
	struct map_pin_bpf *obj;
	int err;

	obj = (struct map_pin_bpf *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = map_pin_bpf__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	map_pin_bpf__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct map_pin_bpf *
map_pin_bpf__open(void)
{
	return map_pin_bpf__open_opts(NULL);
}

static inline int
map_pin_bpf__load(struct map_pin_bpf *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct map_pin_bpf *
map_pin_bpf__open_and_load(void)
{
	struct map_pin_bpf *obj;
	int err;

	obj = map_pin_bpf__open();
	if (!obj)
		return NULL;
	err = map_pin_bpf__load(obj);
	if (err) {
		map_pin_bpf__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
map_pin_bpf__attach(struct map_pin_bpf *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
map_pin_bpf__detach(struct map_pin_bpf *obj)
{
	return bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *map_pin_bpf__elf_bytes(size_t *sz);

static inline int
map_pin_bpf__create_skeleton(struct map_pin_bpf *obj)
{
	struct bpf_object_skeleton *s;
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "map_pin_bpf";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 2;
	s->map_skel_sz = sizeof(*s->maps);
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
	if (!s->maps) {
		err = -ENOMEM;
		goto err;
	}

	s->maps[0].name = "map_kern";
	s->maps[0].map = &obj->maps.map_kern;

	s->maps[1].name = "map_pin_.rodata";
	s->maps[1].map = &obj->maps.rodata;
	s->maps[1].mmaped = (void **)&obj->rodata;

	/* programs */
	s->prog_cnt = 1;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs) {
		err = -ENOMEM;
		goto err;
	}

	s->progs[0].name = "handle_tracepoint";
	s->progs[0].prog = &obj->progs.handle_tracepoint;
	s->progs[0].link = &obj->links.handle_tracepoint;

	s->data = (void *)map_pin_bpf__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *map_pin_bpf__elf_bytes(size_t *sz)
{
	*sz = 8416;
	return (const void *)"\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\xa0\x19\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x1d\0\
\x01\0\xb7\x01\0\0\x41\x01\0\0\x63\x1a\xfc\xff\0\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\
\x02\0\0\xfc\xff\xff\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\x01\0\0\
\0\xbf\x01\0\0\0\0\0\0\xb7\0\0\0\0\0\0\0\x55\x01\x21\0\0\0\0\0\x61\xa3\xfc\xff\
\0\0\0\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x02\0\0\x55\0\0\0\x85\0\0\0\
\x06\0\0\0\xb7\x01\0\0\x05\0\0\0\x63\x1a\xf8\xff\0\0\0\0\xbf\xa2\0\0\0\0\0\0\
\x07\x02\0\0\xfc\xff\xff\xff\xbf\xa3\0\0\0\0\0\0\x07\x03\0\0\xf8\xff\xff\xff\
\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x04\0\0\x01\0\0\0\x85\0\0\0\x02\0\0\0\
\x18\x01\0\0\0\0\0\x80\0\0\0\0\0\0\0\0\x5f\x10\0\0\0\0\0\0\x61\xa4\xfc\xff\0\0\
\0\0\x61\xa3\xf8\xff\0\0\0\0\x15\0\x07\0\0\0\0\0\x18\x01\0\0\x55\0\0\0\0\0\0\0\
\0\0\0\0\xb7\x02\0\0\x42\0\0\0\x85\0\0\0\x06\0\0\0\x18\0\0\0\xff\xff\xff\xff\0\
\0\0\0\0\0\0\0\x05\0\x05\0\0\0\0\0\x18\x01\0\0\x97\0\0\0\0\0\0\0\0\0\0\0\xb7\
\x02\0\0\x3a\0\0\0\x85\0\0\0\x06\0\0\0\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\x44\
\x75\x61\x6c\x20\x42\x53\x44\x2f\x47\x50\x4c\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x66\x61\x69\x6c\x65\x64\
\x20\x74\x6f\x20\x6c\x6f\x6f\x6b\x75\x70\x20\x66\x6f\x72\x20\x6b\x65\x79\x28\
\x25\x64\x29\x20\x69\x6e\x20\x65\x42\x50\x46\x20\x6d\x61\x70\x20\x27\x6d\x61\
\x70\x5f\x6b\x65\x72\x6e\x27\x2e\x20\x54\x72\x79\x69\x6e\x67\x20\x74\x6f\x20\
\x69\x6e\x73\x65\x72\x74\x20\x61\x20\x6e\x65\x77\x20\x76\x61\x6c\x75\x65\x2e\
\x2e\x2e\0\x66\x61\x69\x6c\x65\x64\x20\x74\x6f\x20\x69\x6e\x73\x65\x72\x74\x20\
\x6e\x65\x77\x20\x76\x61\x6c\x75\x65\x28\x25\x64\x29\x20\x66\x6f\x72\x20\x6b\
\x65\x79\x28\x25\x64\x29\x20\x69\x6e\x20\x65\x42\x50\x46\x20\x6d\x61\x70\x20\
\x27\x6d\x61\x70\x5f\x6b\x65\x72\x6e\x27\0\x69\x6e\x73\x65\x72\x74\x65\x64\x20\
\x6e\x65\x77\x20\x76\x61\x6c\x75\x65\x28\x25\x64\x29\x20\x66\x6f\x72\x20\x6b\
\x65\x79\x28\x25\x64\x29\x20\x69\x6e\x20\x65\x42\x50\x46\x20\x6d\x61\x70\x20\
\x27\x6d\x61\x70\x5f\x6b\x65\x72\x6e\x27\0\x5b\0\0\0\x05\0\x08\0\x04\0\0\0\x10\
\0\0\0\x27\0\0\0\x2d\0\0\0\x3f\0\0\0\x04\x08\x10\x04\x11\xc1\x02\x9f\x04\x10\
\x50\x02\x7a\x04\x04\x88\x01\xf0\x01\x02\x7a\x04\0\x04\x40\x68\x01\x51\0\x04\
\x80\x01\x88\x01\x03\x11\x05\x9f\x04\x88\x01\xe0\x01\x02\x7a\0\0\x04\xc8\x01\
\xe0\x01\x0d\x70\0\xa8\xab\x80\x80\0\xa8\xaf\x80\x80\0\x9f\0\x01\x11\x01\x25\
\x25\x13\x05\x03\x25\x72\x17\x10\x17\x1b\x25\x11\x1b\x12\x06\x73\x17\x74\x17\
\x8c\x01\x17\0\0\x02\x24\0\x03\x25\x3e\x0b\x0b\x0b\0\0\x03\x34\0\x03\x25\x49\
\x13\x3f\x19\x3a\x0b\x3b\x0b\x02\x18\0\0\x04\x01\x01\x49\x13\0\0\x05\x21\0\x49\
\x13\x37\x0b\0\0\x06\x24\0\x03\x25\x0b\x0b\x3e\x0b\0\0\x07\x2e\x01\x11\x1b\x12\
\x06\x40\x18\x7a\x19\x03\x25\x3a\x0b\x3b\x0b\x27\x19\x49\x13\x3f\x19\0\0\x08\
\x34\0\x03\x25\x49\x13\x3a\x0b\x3b\x0b\x02\x18\0\0\x09\x05\0\x03\x25\x3a\x0b\
\x3b\x0b\x49\x13\0\0\x0a\x34\0\x02\x22\x03\x25\x3a\x0b\x3b\x0b\x49\x13\0\0\x0b\
\x0b\x01\x55\x23\0\0\x0c\x26\0\x49\x13\0\0\x0d\x13\x01\x0b\x0b\x3a\x0b\x3b\x0b\
\0\0\x0e\x0d\0\x03\x25\x49\x13\x3a\x0b\x3b\x0b\x38\x0b\0\0\x0f\x0f\0\x49\x13\0\
\0\x10\x34\0\x03\x25\x49\x13\x3a\x0b\x3b\x0b\0\0\x11\x15\x01\x49\x13\x27\x19\0\
\0\x12\x05\0\x49\x13\0\0\x13\x0f\0\0\0\x14\x26\0\0\0\x15\x18\0\0\0\x16\x16\0\
\x49\x13\x03\x25\x3a\x0b\x3b\x0b\0\0\x17\x04\x01\x49\x13\x0b\x0b\x3a\x0b\x3b\
\x05\0\0\x18\x28\0\x03\x25\x1c\x0f\0\0\0\xcf\x01\0\0\x05\0\x01\x08\0\0\0\0\x01\
\0\x0c\0\x01\x08\0\0\0\0\0\0\0\x02\x05\x60\x01\0\0\x08\0\0\0\x0c\0\0\0\x0c\0\0\
\0\x02\x1b\x07\x08\x02\x1a\x07\x04\x03\x03\x3e\0\0\0\0\x04\x02\xa1\0\x04\x4a\0\
\0\0\x05\x4e\0\0\0\x0d\0\x02\x04\x06\x01\x06\x05\x08\x07\x07\x05\x60\x01\0\0\
\x01\x5a\x1c\0\x0f\x29\x01\0\0\x08\x06\xb2\0\0\0\0\x13\x02\xa1\x01\x08\x06\xc3\
\0\0\0\0\x17\x02\xa1\x02\x08\x06\xcf\0\0\0\0\x1a\x02\xa1\x03\x09\x1f\0\x0f\x4f\
\x01\0\0\x0a\0\x0a\0\x10\x29\x01\0\0\x0a\x01\x0b\0\x11\x2d\x01\0\0\x0b\0\x0a\
\x02\x1d\0\x14\x29\x01\0\0\x0a\x03\x1e\0\x15\x29\x01\0\0\0\0\x04\xbe\0\0\0\x05\
\x4e\0\0\0\x55\0\x0c\x4a\0\0\0\x04\xbe\0\0\0\x05\x4e\0\0\0\x42\0\x04\xbe\0\0\0\
\x05\x4e\0\0\0\x3a\0\x03\x07\xe6\0\0\0\0\x0c\x02\xa1\x04\x0d\x28\0\x06\x0e\x08\
\x18\x01\0\0\0\x07\0\x0e\x0a\x2d\x01\0\0\0\x08\x08\x0e\x0b\x2d\x01\0\0\0\x09\
\x10\x0e\x0c\x18\x01\0\0\0\x0a\x18\x0e\x0d\x18\x01\0\0\0\x0b\x20\0\x0f\x1d\x01\
\0\0\x04\x29\x01\0\0\x05\x4e\0\0\0\x01\0\x02\x09\x05\x04\x0f\x29\x01\0\0\x10\
\x0e\x3a\x01\0\0\x01\x33\x0f\x3f\x01\0\0\x11\x4f\x01\0\0\x12\x4f\x01\0\0\x12\
\x50\x01\0\0\0\x13\x0f\x55\x01\0\0\x14\x10\x0f\x5e\x01\0\0\x01\xac\x0f\x63\x01\
\0\0\x11\x74\x01\0\0\x12\x78\x01\0\0\x12\x7d\x01\0\0\x15\0\x02\x10\x05\x08\x0f\
\xbe\0\0\0\x16\x85\x01\0\0\x12\x02\x1b\x02\x11\x07\x04\x10\x13\x91\x01\0\0\x01\
\x49\x0f\x96\x01\0\0\x11\x74\x01\0\0\x12\x4f\x01\0\0\x12\x50\x01\0\0\x12\x50\
\x01\0\0\x12\xb0\x01\0\0\0\x16\xb8\x01\0\0\x15\x02\x1f\x02\x14\x07\x08\x17\x85\
\x01\0\0\x04\x03\x91\x04\x18\x16\0\x18\x17\x01\x18\x18\x02\x18\x19\x04\0\0\x16\
\0\0\0\x05\0\x08\0\x01\0\0\0\x04\0\0\0\x04\x50\x90\x01\x04\xa8\x01\xd8\x02\0\
\x84\0\0\0\x05\0\0\0\0\0\0\0\x25\0\0\0\x33\0\0\0\x5e\0\0\0\x66\0\0\0\x6b\0\0\0\
\x7f\0\0\0\x87\0\0\0\x90\0\0\0\x95\0\0\0\x99\0\0\0\x9d\0\0\0\xa3\0\0\0\xaf\0\0\
\0\xb7\0\0\0\xcb\0\0\0\xdc\0\0\0\xe1\0\0\0\xee\0\0\0\xf4\0\0\0\x08\x01\0\0\x1b\
\x01\0\0\x21\x01\0\0\x29\x01\0\0\x35\x01\0\0\x3f\x01\0\0\x4a\x01\0\0\x5d\x01\0\
\0\x70\x01\0\0\x82\x01\0\0\x8c\x01\0\0\x93\x01\0\0\x55\x62\x75\x6e\x74\x75\x20\
\x63\x6c\x61\x6e\x67\x20\x76\x65\x72\x73\x69\x6f\x6e\x20\x31\x34\x2e\x30\x2e\
\x30\x2d\x31\x75\x62\x75\x6e\x74\x75\x31\0\x6d\x61\x70\x5f\x70\x69\x6e\x2e\x62\
\x70\x66\x2e\x63\0\x2f\x68\x6f\x6d\x65\x2f\x6c\x65\x6f\x6e\x61\x72\x64\x6f\x2f\
\x53\x63\x72\x69\x76\x61\x6e\x69\x61\x2f\x70\x72\x6f\x76\x65\x2f\x66\x6f\x6e\
\x74\x61\x6e\x61\x2f\x6d\x61\x70\0\x4c\x49\x43\x45\x4e\x53\x45\0\x63\x68\x61\
\x72\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\
\x5f\0\x5f\x5f\x5f\x5f\x66\x6d\x74\0\x6d\x61\x70\x5f\x6b\x65\x72\x6e\0\x74\x79\
\x70\x65\0\x69\x6e\x74\0\x6b\x65\x79\0\x76\x61\x6c\x75\x65\0\x6d\x61\x78\x5f\
\x65\x6e\x74\x72\x69\x65\x73\0\x70\x69\x6e\x6e\x69\x6e\x67\0\x62\x70\x66\x5f\
\x6d\x61\x70\x5f\x6c\x6f\x6f\x6b\x75\x70\x5f\x65\x6c\x65\x6d\0\x62\x70\x66\x5f\
\x74\x72\x61\x63\x65\x5f\x70\x72\x69\x6e\x74\x6b\0\x6c\x6f\x6e\x67\0\x75\x6e\
\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\x5f\x5f\x75\x33\x32\0\x62\x70\x66\
\x5f\x6d\x61\x70\x5f\x75\x70\x64\x61\x74\x65\x5f\x65\x6c\x65\x6d\0\x75\x6e\x73\
\x69\x67\x6e\x65\x64\x20\x6c\x6f\x6e\x67\x20\x6c\x6f\x6e\x67\0\x5f\x5f\x75\x36\
\x34\0\x42\x50\x46\x5f\x41\x4e\x59\0\x42\x50\x46\x5f\x4e\x4f\x45\x58\x49\x53\
\x54\0\x42\x50\x46\x5f\x45\x58\x49\x53\x54\0\x42\x50\x46\x5f\x46\x5f\x4c\x4f\
\x43\x4b\0\x44\x57\x5f\x41\x54\x45\x5f\x75\x6e\x73\x69\x67\x6e\x65\x64\x5f\x33\
\x32\0\x44\x57\x5f\x41\x54\x45\x5f\x75\x6e\x73\x69\x67\x6e\x65\x64\x5f\x36\x34\
\0\x68\x61\x6e\x64\x6c\x65\x5f\x74\x72\x61\x63\x65\x70\x6f\x69\x6e\x74\0\x6e\
\x65\x77\x5f\x76\x61\x6c\x75\x65\0\x72\x65\x73\x75\x6c\x74\0\x63\x74\x78\0\x34\
\0\0\0\x05\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x55\0\0\0\0\0\0\0\x97\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x9f\xeb\x01\0\x18\0\0\0\0\0\0\0\
\xf0\x01\0\0\xf0\x01\0\0\x7d\x03\0\0\0\0\0\0\0\0\0\x02\x03\0\0\0\x01\0\0\0\0\0\
\0\x01\x04\0\0\0\x20\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\x01\
\0\0\0\x05\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\x02\x02\0\0\0\0\0\
\0\0\x05\0\0\x04\x28\0\0\0\x19\0\0\0\x01\0\0\0\0\0\0\0\x1e\0\0\0\x05\0\0\0\x40\
\0\0\0\x22\0\0\0\x05\0\0\0\x80\0\0\0\x28\0\0\0\x01\0\0\0\xc0\0\0\0\x34\0\0\0\
\x01\0\0\0\0\x01\0\0\x3c\0\0\0\0\0\0\x0e\x06\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\x02\
\0\0\0\0\0\0\0\0\x01\0\0\x0d\x02\0\0\0\x45\0\0\0\x08\0\0\0\x49\0\0\0\x01\0\0\
\x0c\x09\0\0\0\x08\x03\0\0\0\0\0\x01\x01\0\0\0\x08\0\0\x01\0\0\0\0\0\0\0\x03\0\
\0\0\0\x0b\0\0\0\x04\0\0\0\x0d\0\0\0\x0d\x03\0\0\0\0\0\x0e\x0c\0\0\0\x01\0\0\0\
\0\0\0\0\0\0\0\x0a\x0b\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x0e\0\0\0\x04\0\0\0\x55\
\0\0\0\x15\x03\0\0\0\0\0\x0e\x0f\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x0e\0\
\0\0\x04\0\0\0\x42\0\0\0\x2f\x03\0\0\0\0\0\x0e\x11\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x03\0\0\0\0\x0e\0\0\0\x04\0\0\0\x3a\0\0\0\x4b\x03\0\0\0\0\0\x0e\x13\0\0\0\0\0\
\0\0\x67\x03\0\0\x01\0\0\x0f\0\0\0\0\x07\0\0\0\0\0\0\0\x28\0\0\0\x6d\x03\0\0\
\x03\0\0\x0f\0\0\0\0\x10\0\0\0\0\0\0\0\x55\0\0\0\x12\0\0\0\x55\0\0\0\x42\0\0\0\
\x14\0\0\0\x97\0\0\0\x3a\0\0\0\x75\x03\0\0\x01\0\0\x0f\0\0\0\0\x0d\0\0\0\0\0\0\
\0\x0d\0\0\0\0\x69\x6e\x74\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\
\x5f\x54\x59\x50\x45\x5f\x5f\0\x74\x79\x70\x65\0\x6b\x65\x79\0\x76\x61\x6c\x75\
\x65\0\x6d\x61\x78\x5f\x65\x6e\x74\x72\x69\x65\x73\0\x70\x69\x6e\x6e\x69\x6e\
\x67\0\x6d\x61\x70\x5f\x6b\x65\x72\x6e\0\x63\x74\x78\0\x68\x61\x6e\x64\x6c\x65\
\x5f\x74\x72\x61\x63\x65\x70\x6f\x69\x6e\x74\0\x74\x72\x61\x63\x65\x70\x6f\x69\
\x6e\x74\x2f\x73\x79\x73\x63\x61\x6c\x6c\x73\x2f\x73\x79\x73\x5f\x65\x6e\x74\
\x65\x72\x5f\x65\x78\x65\x63\x76\x65\0\x2f\x68\x6f\x6d\x65\x2f\x6c\x65\x6f\x6e\
\x61\x72\x64\x6f\x2f\x53\x63\x72\x69\x76\x61\x6e\x69\x61\x2f\x70\x72\x6f\x76\
\x65\x2f\x66\x6f\x6e\x74\x61\x6e\x61\x2f\x6d\x61\x70\x2f\x6d\x61\x70\x5f\x70\
\x69\x6e\x2e\x62\x70\x66\x2e\x63\0\x69\x6e\x74\x20\x68\x61\x6e\x64\x6c\x65\x5f\
\x74\x72\x61\x63\x65\x70\x6f\x69\x6e\x74\x28\x76\x6f\x69\x64\x20\x2a\x63\x74\
\x78\x29\x20\x7b\0\x20\x20\x20\x20\x69\x6e\x74\x20\x6b\x65\x79\x20\x3d\x20\x33\
\x32\x31\x3b\0\x20\x20\x20\x20\x69\x6e\x74\x20\x2a\x76\x61\x6c\x75\x65\x20\x3d\
\x20\x62\x70\x66\x5f\x6d\x61\x70\x5f\x6c\x6f\x6f\x6b\x75\x70\x5f\x65\x6c\x65\
\x6d\x28\x26\x6d\x61\x70\x5f\x6b\x65\x72\x6e\x2c\x20\x26\x6b\x65\x79\x29\x3b\0\
\x20\x20\x20\x20\x69\x66\x20\x28\x21\x76\x61\x6c\x75\x65\x29\x20\x7b\0\x20\x20\
\x20\x20\x20\x20\x20\x20\x62\x70\x66\x5f\x70\x72\x69\x6e\x74\x6b\x28\x22\x66\
\x61\x69\x6c\x65\x64\x20\x74\x6f\x20\x6c\x6f\x6f\x6b\x75\x70\x20\x66\x6f\x72\
\x20\x6b\x65\x79\x28\x25\x64\x29\x20\x69\x6e\x20\x65\x42\x50\x46\x20\x6d\x61\
\x70\x20\x5c\x27\x6d\x61\x70\x5f\x6b\x65\x72\x6e\x5c\x27\x2e\x20\x54\x72\x79\
\x69\x6e\x67\x20\x74\x6f\x20\x69\x6e\x73\x65\x72\x74\x20\x61\x20\x6e\x65\x77\
\x20\x76\x61\x6c\x75\x65\x2e\x2e\x2e\x22\x2c\x20\x6b\x65\x79\x29\x3b\0\x20\x20\
\x20\x20\x20\x20\x20\x20\x69\x6e\x74\x20\x6e\x65\x77\x5f\x76\x61\x6c\x75\x65\
\x20\x3d\x20\x35\x3b\0\x20\x20\x20\x20\x20\x20\x20\x20\x69\x6e\x74\x20\x72\x65\
\x73\x75\x6c\x74\x20\x3d\x20\x62\x70\x66\x5f\x6d\x61\x70\x5f\x75\x70\x64\x61\
\x74\x65\x5f\x65\x6c\x65\x6d\x28\x26\x6d\x61\x70\x5f\x6b\x65\x72\x6e\x2c\x20\
\x26\x6b\x65\x79\x2c\x20\x26\x6e\x65\x77\x5f\x76\x61\x6c\x75\x65\x2c\x20\x42\
\x50\x46\x5f\x4e\x4f\x45\x58\x49\x53\x54\x29\x3b\0\x20\x20\x20\x20\x20\x20\x20\
\x20\x69\x66\x20\x28\x72\x65\x73\x75\x6c\x74\x20\x3c\x20\x30\x29\x20\x7b\0\x20\
\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x62\x70\x66\x5f\x70\x72\x69\x6e\
\x74\x6b\x28\x22\x66\x61\x69\x6c\x65\x64\x20\x74\x6f\x20\x69\x6e\x73\x65\x72\
\x74\x20\x6e\x65\x77\x20\x76\x61\x6c\x75\x65\x28\x25\x64\x29\x20\x66\x6f\x72\
\x20\x6b\x65\x79\x28\x25\x64\x29\x20\x69\x6e\x20\x65\x42\x50\x46\x20\x6d\x61\
\x70\x20\x5c\x27\x6d\x61\x70\x5f\x6b\x65\x72\x6e\x5c\x27\x22\x2c\x20\x6e\x65\
\x77\x5f\x76\x61\x6c\x75\x65\x2c\x20\x6b\x65\x79\x29\x3b\0\x20\x20\x20\x20\x20\
\x20\x20\x20\x62\x70\x66\x5f\x70\x72\x69\x6e\x74\x6b\x28\x22\x69\x6e\x73\x65\
\x72\x74\x65\x64\x20\x6e\x65\x77\x20\x76\x61\x6c\x75\x65\x28\x25\x64\x29\x20\
\x66\x6f\x72\x20\x6b\x65\x79\x28\x25\x64\x29\x20\x69\x6e\x20\x65\x42\x50\x46\
\x20\x6d\x61\x70\x20\x5c\x27\x6d\x61\x70\x5f\x6b\x65\x72\x6e\x5c\x27\x22\x2c\
\x20\x6e\x65\x77\x5f\x76\x61\x6c\x75\x65\x2c\x20\x6b\x65\x79\x29\x3b\0\x7d\0\
\x63\x68\x61\x72\0\x4c\x49\x43\x45\x4e\x53\x45\0\x68\x61\x6e\x64\x6c\x65\x5f\
\x74\x72\x61\x63\x65\x70\x6f\x69\x6e\x74\x2e\x5f\x5f\x5f\x5f\x66\x6d\x74\0\x68\
\x61\x6e\x64\x6c\x65\x5f\x74\x72\x61\x63\x65\x70\x6f\x69\x6e\x74\x2e\x5f\x5f\
\x5f\x5f\x66\x6d\x74\x2e\x31\0\x68\x61\x6e\x64\x6c\x65\x5f\x74\x72\x61\x63\x65\
\x70\x6f\x69\x6e\x74\x2e\x5f\x5f\x5f\x5f\x66\x6d\x74\x2e\x32\0\x2e\x6d\x61\x70\
\x73\0\x2e\x72\x6f\x64\x61\x74\x61\0\x6c\x69\x63\x65\x6e\x73\x65\0\0\0\0\x9f\
\xeb\x01\0\x20\0\0\0\0\0\0\0\x14\0\0\0\x14\0\0\0\xfc\0\0\0\x10\x01\0\0\0\0\0\0\
\x08\0\0\0\x5b\0\0\0\x01\0\0\0\0\0\0\0\x0a\0\0\0\x10\0\0\0\x5b\0\0\0\x0f\0\0\0\
\0\0\0\0\x80\0\0\0\xb9\0\0\0\0\x3c\0\0\x08\0\0\0\x80\0\0\0\xdc\0\0\0\x09\x40\0\
\0\x18\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\0\x20\0\0\0\x80\0\0\0\xef\0\0\0\x12\x44\0\
\0\x48\0\0\0\x80\0\0\0\x26\x01\0\0\x09\x48\0\0\x50\0\0\0\x80\0\0\0\x38\x01\0\0\
\x09\x4c\0\0\x80\0\0\0\x80\0\0\0\xab\x01\0\0\x0d\x50\0\0\x90\0\0\0\x80\0\0\0\0\
\0\0\0\0\0\0\0\xa8\0\0\0\x80\0\0\0\xc6\x01\0\0\x16\x54\0\0\xd8\0\0\0\x80\0\0\0\
\x1a\x02\0\0\x14\x58\0\0\xe0\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\0\xf0\0\0\0\x80\0\0\
\0\x1a\x02\0\0\x0d\x58\0\0\xf8\0\0\0\x80\0\0\0\x34\x02\0\0\x0d\x5c\0\0\x30\x01\
\0\0\x80\0\0\0\xa3\x02\0\0\x09\x68\0\0\x58\x01\0\0\x80\0\0\0\x06\x03\0\0\x01\
\x78\0\0\0\0\0\0\x0c\0\0\0\xff\xff\xff\xff\x04\0\x08\0\x08\x7c\x0b\0\x14\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x60\x01\0\0\0\0\0\0\xf7\0\0\0\x05\0\x08\0\x82\0\0\0\
\x08\x01\x01\xfb\x0e\x0d\0\x01\x01\x01\x01\0\0\0\x01\0\0\x01\x01\x01\x1f\x04\0\
\0\0\0\x2b\0\0\0\x3c\0\0\0\x55\0\0\0\x03\x01\x1f\x02\x0f\x05\x1e\x04\x68\0\0\0\
\0\xf4\x3f\xff\xb9\x2a\x5c\x0f\xbc\x0c\xfd\x54\x45\x6e\xd6\xdb\xc5\x76\0\0\0\
\x01\xad\x8f\xf3\x75\x51\x06\xb5\x33\xb4\x46\x15\x9c\x41\x0c\x59\x6d\x88\0\0\0\
\x02\xb8\x10\xf2\x70\x73\x3e\x10\x63\x19\xb6\x7e\xf5\x12\xc6\x24\x6e\x93\0\0\0\
\x03\x68\x9c\x3d\xa7\x7a\xc6\xe6\xdf\xcb\xd7\x71\xfd\x67\x06\xf6\x60\x04\0\0\
\x09\x02\0\0\0\0\0\0\0\0\x03\x0e\x01\x05\x09\x0a\x21\x06\x03\x70\x20\x05\x12\
\x06\x03\x11\x2e\x06\x03\x6f\x4a\x05\x09\x06\x03\x12\x20\x21\x06\x03\x6d\x58\
\x05\x0d\x06\x03\x14\x20\x06\x03\x6c\x20\x05\x16\x06\x03\x15\x4a\x06\x03\x6b\
\x4a\x05\x14\x06\x03\x16\x2e\x05\0\x06\x03\x6a\x20\x05\x0d\x03\x16\x2e\x06\x21\
\x06\x03\x69\x4a\x05\x09\x06\x03\x1a\x3c\x06\x03\x66\x4a\x05\x01\x06\x03\x1e\
\x20\x02\x01\0\x01\x01\x2f\x68\x6f\x6d\x65\x2f\x6c\x65\x6f\x6e\x61\x72\x64\x6f\
\x2f\x53\x63\x72\x69\x76\x61\x6e\x69\x61\x2f\x70\x72\x6f\x76\x65\x2f\x66\x6f\
\x6e\x74\x61\x6e\x61\x2f\x6d\x61\x70\0\x2f\x75\x73\x72\x2f\x69\x6e\x63\x6c\x75\
\x64\x65\x2f\x62\x70\x66\0\x2f\x75\x73\x72\x2f\x69\x6e\x63\x6c\x75\x64\x65\x2f\
\x61\x73\x6d\x2d\x67\x65\x6e\x65\x72\x69\x63\0\x2f\x75\x73\x72\x2f\x69\x6e\x63\
\x6c\x75\x64\x65\x2f\x6c\x69\x6e\x75\x78\0\x6d\x61\x70\x5f\x70\x69\x6e\x2e\x62\
\x70\x66\x2e\x63\0\x62\x70\x66\x5f\x68\x65\x6c\x70\x65\x72\x5f\x64\x65\x66\x73\
\x2e\x68\0\x69\x6e\x74\x2d\x6c\x6c\x36\x34\x2e\x68\0\x62\x70\x66\x2e\x68\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x2f\x01\0\0\x04\0\xf1\xff\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x66\x01\0\0\0\0\x03\0\x58\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x34\0\0\0\x01\
\0\x07\0\0\0\0\0\0\0\0\0\x55\0\0\0\0\0\0\0\x6d\x01\0\0\0\0\x03\0\x30\x01\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x90\x01\0\0\x01\0\x07\0\x55\0\0\0\0\0\0\0\x42\0\0\0\0\0\
\0\0\x74\x01\0\0\x01\0\x07\0\x97\0\0\0\0\0\0\0\x3a\0\0\0\0\0\0\0\0\0\0\0\x03\0\
\x07\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x08\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x03\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\
\x0c\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0d\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x03\0\x0f\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\
\x10\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x16\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x03\0\x18\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\
\x1a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x22\0\0\0\x12\0\x03\0\0\0\0\0\0\0\0\0\
\x60\x01\0\0\0\0\0\0\xc6\0\0\0\x11\0\x06\0\0\0\0\0\0\0\0\0\x28\0\0\0\0\0\0\0\
\x5e\x01\0\0\x11\0\x05\0\0\0\0\0\0\0\0\0\x0d\0\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\
\x01\0\0\0\x13\0\0\0\x58\0\0\0\0\0\0\0\x01\0\0\0\x08\0\0\0\xa8\0\0\0\0\0\0\0\
\x01\0\0\0\x13\0\0\0\xf8\0\0\0\0\0\0\0\x01\0\0\0\x08\0\0\0\x30\x01\0\0\0\0\0\0\
\x01\0\0\0\x08\0\0\0\x08\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x11\0\0\0\0\0\0\0\
\x03\0\0\0\x0c\0\0\0\x15\0\0\0\0\0\0\0\x03\0\0\0\x10\0\0\0\x1f\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x23\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x27\0\0\0\0\0\0\0\
\x03\0\0\0\x09\0\0\0\x08\0\0\0\0\0\0\0\x03\0\0\0\x0d\0\0\0\x0c\0\0\0\0\0\0\0\
\x03\0\0\0\x0d\0\0\0\x10\0\0\0\0\0\0\0\x03\0\0\0\x0d\0\0\0\x14\0\0\0\0\0\0\0\
\x03\0\0\0\x0d\0\0\0\x18\0\0\0\0\0\0\0\x03\0\0\0\x0d\0\0\0\x1c\0\0\0\0\0\0\0\
\x03\0\0\0\x0d\0\0\0\x20\0\0\0\0\0\0\0\x03\0\0\0\x0d\0\0\0\x24\0\0\0\0\0\0\0\
\x03\0\0\0\x0d\0\0\0\x28\0\0\0\0\0\0\0\x03\0\0\0\x0d\0\0\0\x2c\0\0\0\0\0\0\0\
\x03\0\0\0\x0d\0\0\0\x30\0\0\0\0\0\0\0\x03\0\0\0\x0d\0\0\0\x34\0\0\0\0\0\0\0\
\x03\0\0\0\x0d\0\0\0\x38\0\0\0\0\0\0\0\x03\0\0\0\x0d\0\0\0\x3c\0\0\0\0\0\0\0\
\x03\0\0\0\x0d\0\0\0\x40\0\0\0\0\0\0\0\x03\0\0\0\x0d\0\0\0\x44\0\0\0\0\0\0\0\
\x03\0\0\0\x0d\0\0\0\x48\0\0\0\0\0\0\0\x03\0\0\0\x0d\0\0\0\x4c\0\0\0\0\0\0\0\
\x03\0\0\0\x0d\0\0\0\x50\0\0\0\0\0\0\0\x03\0\0\0\x0d\0\0\0\x54\0\0\0\0\0\0\0\
\x03\0\0\0\x0d\0\0\0\x58\0\0\0\0\0\0\0\x03\0\0\0\x0d\0\0\0\x5c\0\0\0\0\0\0\0\
\x03\0\0\0\x0d\0\0\0\x60\0\0\0\0\0\0\0\x03\0\0\0\x0d\0\0\0\x64\0\0\0\0\0\0\0\
\x03\0\0\0\x0d\0\0\0\x68\0\0\0\0\0\0\0\x03\0\0\0\x0d\0\0\0\x6c\0\0\0\0\0\0\0\
\x03\0\0\0\x0d\0\0\0\x70\0\0\0\0\0\0\0\x03\0\0\0\x0d\0\0\0\x74\0\0\0\0\0\0\0\
\x03\0\0\0\x0d\0\0\0\x78\0\0\0\0\0\0\0\x03\0\0\0\x0d\0\0\0\x7c\0\0\0\0\0\0\0\
\x03\0\0\0\x0d\0\0\0\x80\0\0\0\0\0\0\0\x03\0\0\0\x0d\0\0\0\x84\0\0\0\0\0\0\0\
\x03\0\0\0\x0d\0\0\0\x08\0\0\0\0\0\0\0\x02\0\0\0\x14\0\0\0\x10\0\0\0\0\0\0\0\
\x02\0\0\0\x08\0\0\0\x18\0\0\0\0\0\0\0\x02\0\0\0\x08\0\0\0\x20\0\0\0\0\0\0\0\
\x02\0\0\0\x08\0\0\0\x28\0\0\0\0\0\0\0\x02\0\0\0\x13\0\0\0\x30\0\0\0\0\0\0\0\
\x02\0\0\0\x02\0\0\0\xb8\x01\0\0\0\0\0\0\x04\0\0\0\x13\0\0\0\xd0\x01\0\0\0\0\0\
\0\x03\0\0\0\x08\0\0\0\xdc\x01\0\0\0\0\0\0\x03\0\0\0\x08\0\0\0\xe8\x01\0\0\0\0\
\0\0\x03\0\0\0\x08\0\0\0\0\x02\0\0\0\0\0\0\x04\0\0\0\x14\0\0\0\x2c\0\0\0\0\0\0\
\0\x04\0\0\0\x02\0\0\0\x40\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x50\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\x60\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x70\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\x80\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x90\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\xa0\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xb0\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\xc0\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xd0\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\xe0\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xf0\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\0\x01\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x10\x01\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\x20\x01\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x14\0\0\0\0\0\0\0\
\x03\0\0\0\x0f\0\0\0\x18\0\0\0\0\0\0\0\x02\0\0\0\x02\0\0\0\x22\0\0\0\0\0\0\0\
\x03\0\0\0\x11\0\0\0\x26\0\0\0\0\0\0\0\x03\0\0\0\x11\0\0\0\x2a\0\0\0\0\0\0\0\
\x03\0\0\0\x11\0\0\0\x2e\0\0\0\0\0\0\0\x03\0\0\0\x11\0\0\0\x3a\0\0\0\0\0\0\0\
\x03\0\0\0\x11\0\0\0\x4f\0\0\0\0\0\0\0\x03\0\0\0\x11\0\0\0\x64\0\0\0\0\0\0\0\
\x03\0\0\0\x11\0\0\0\x79\0\0\0\0\0\0\0\x03\0\0\0\x11\0\0\0\x93\0\0\0\0\0\0\0\
\x02\0\0\0\x02\0\0\0\x12\x14\x13\x04\x06\x07\0\x2e\x64\x65\x62\x75\x67\x5f\x61\
\x62\x62\x72\x65\x76\0\x2e\x74\x65\x78\x74\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\
\x2e\x65\x78\x74\0\x68\x61\x6e\x64\x6c\x65\x5f\x74\x72\x61\x63\x65\x70\x6f\x69\
\x6e\x74\0\x68\x61\x6e\x64\x6c\x65\x5f\x74\x72\x61\x63\x65\x70\x6f\x69\x6e\x74\
\x2e\x5f\x5f\x5f\x5f\x66\x6d\x74\0\x2e\x64\x65\x62\x75\x67\x5f\x72\x6e\x67\x6c\
\x69\x73\x74\x73\0\x2e\x64\x65\x62\x75\x67\x5f\x6c\x6f\x63\x6c\x69\x73\x74\x73\
\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x73\x74\x72\x5f\x6f\x66\x66\x73\
\x65\x74\x73\0\x2e\x6d\x61\x70\x73\0\x2e\x64\x65\x62\x75\x67\x5f\x73\x74\x72\0\
\x2e\x64\x65\x62\x75\x67\x5f\x6c\x69\x6e\x65\x5f\x73\x74\x72\0\x2e\x72\x65\x6c\
\x2e\x64\x65\x62\x75\x67\x5f\x61\x64\x64\x72\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\
\x75\x67\x5f\x69\x6e\x66\x6f\0\x6d\x61\x70\x5f\x6b\x65\x72\x6e\0\x2e\x6c\x6c\
\x76\x6d\x5f\x61\x64\x64\x72\x73\x69\x67\0\x2e\x72\x65\x6c\x74\x72\x61\x63\x65\
\x70\x6f\x69\x6e\x74\x2f\x73\x79\x73\x63\x61\x6c\x6c\x73\x2f\x73\x79\x73\x5f\
\x65\x6e\x74\x65\x72\x5f\x65\x78\x65\x63\x76\x65\0\x6c\x69\x63\x65\x6e\x73\x65\
\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x6c\x69\x6e\x65\0\x2e\x72\x65\
\x6c\x2e\x64\x65\x62\x75\x67\x5f\x66\x72\x61\x6d\x65\0\x6d\x61\x70\x5f\x70\x69\
\x6e\x2e\x62\x70\x66\x2e\x63\0\x2e\x73\x74\x72\x74\x61\x62\0\x2e\x73\x79\x6d\
\x74\x61\x62\0\x2e\x72\x6f\x64\x61\x74\x61\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\0\
\x4c\x49\x43\x45\x4e\x53\x45\0\x4c\x42\x42\x30\x5f\x34\0\x4c\x42\x42\x30\x5f\
\x33\0\x68\x61\x6e\x64\x6c\x65\x5f\x74\x72\x61\x63\x65\x70\x6f\x69\x6e\x74\x2e\
\x5f\x5f\x5f\x5f\x66\x6d\x74\x2e\x32\0\x68\x61\x6e\x64\x6c\x65\x5f\x74\x72\x61\
\x63\x65\x70\x6f\x69\x6e\x74\x2e\x5f\x5f\x5f\x5f\x66\x6d\x74\x2e\x31\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x3d\x01\0\0\x03\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xee\x17\0\0\0\0\0\0\xac\x01\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0f\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\xe1\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x40\0\0\0\0\0\0\0\x60\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\xdd\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xd8\x12\0\0\0\
\0\0\0\x50\0\0\0\0\0\0\0\x1c\0\0\0\x03\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\
\0\x06\x01\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa0\x01\0\0\0\0\0\0\
\x0d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\
\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb0\x01\0\0\0\0\0\0\x28\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x4d\x01\0\0\x01\0\0\0\
\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xd8\x01\0\0\0\0\0\0\xd1\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x5e\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\xa9\x02\0\0\0\0\0\0\x5f\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x08\x03\0\0\0\0\0\0\x16\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\xba\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x1e\x04\0\0\
\0\0\0\0\xd3\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\xb6\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x28\x13\0\0\0\0\0\0\x60\
\0\0\0\0\0\0\0\x1c\0\0\0\x0a\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x4e\0\0\
\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xf1\x05\0\0\0\0\0\0\x1a\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x72\0\0\0\x01\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0b\x06\0\0\0\0\0\0\x88\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x6e\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x88\x13\0\0\0\0\0\0\0\x02\0\0\0\0\0\0\x1c\0\0\0\x0d\0\0\0\x08\0\
\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x8b\0\0\0\x01\0\0\0\x30\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x93\x06\0\0\0\0\0\0\x97\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\
\0\x01\0\0\0\0\0\0\0\xaa\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x2a\
\x08\0\0\0\0\0\0\x38\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\xa6\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x88\x15\0\0\0\0\0\
\0\x60\0\0\0\0\0\0\0\x1c\0\0\0\x10\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\
\x59\x01\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x64\x08\0\0\0\0\0\0\x85\
\x05\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x55\x01\0\0\
\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe8\x15\0\0\0\0\0\0\x50\0\0\0\0\0\
\0\0\x1c\0\0\0\x12\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x19\0\0\0\x01\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xec\x0d\0\0\0\0\0\0\x30\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x15\0\0\0\x09\0\0\0\x40\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x38\x16\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\x1c\0\0\0\x14\0\0\
\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x22\x01\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x20\x0f\0\0\0\0\0\0\x28\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x1e\x01\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x38\x17\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x1c\0\0\0\x16\0\0\0\x08\0\0\0\0\0\0\0\
\x10\0\0\0\0\0\0\0\x12\x01\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x48\
\x0f\0\0\0\0\0\0\xfb\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x0e\x01\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x58\x17\0\0\0\0\
\0\0\x90\0\0\0\0\0\0\0\x1c\0\0\0\x18\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\
\x96\0\0\0\x01\0\0\0\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x43\x10\0\0\0\0\0\0\x99\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\xcf\0\0\0\
\x03\x4c\xff\x6f\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\0\0\xe8\x17\0\0\0\0\0\0\x06\0\0\
\0\0\0\0\0\x1c\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x45\x01\0\0\x02\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe0\x10\0\0\0\0\0\0\xf8\x01\0\0\0\0\0\0\
\x01\0\0\0\x12\0\0\0\x08\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0";
}

#ifdef __cplusplus
struct map_pin_bpf *map_pin_bpf::open(const struct bpf_object_open_opts *opts) { return map_pin_bpf__open_opts(opts); }
struct map_pin_bpf *map_pin_bpf::open_and_load() { return map_pin_bpf__open_and_load(); }
int map_pin_bpf::load(struct map_pin_bpf *skel) { return map_pin_bpf__load(skel); }
int map_pin_bpf::attach(struct map_pin_bpf *skel) { return map_pin_bpf__attach(skel); }
void map_pin_bpf::detach(struct map_pin_bpf *skel) { map_pin_bpf__detach(skel); }
void map_pin_bpf::destroy(struct map_pin_bpf *skel) { map_pin_bpf__destroy(skel); }
const void *map_pin_bpf::elf_bytes(size_t *sz) { return map_pin_bpf__elf_bytes(sz); }
#endif /* __cplusplus */

__attribute__((unused)) static void
map_pin_bpf__assert(struct map_pin_bpf *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif /* __MAP_PIN_BPF_SKEL_H__ */
