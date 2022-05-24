NAME="$1"

set -e

# building the $NAME.bpf.o BPF object file
clang -g -Wall -O2 -target bpf -c "$NAME".bpf.c -o "$NAME".bpf.o

# building the BPF skeleton
bpftool gen skeleton "$NAME".bpf.o > "$NAME".skel.h

# compiling the $NAME.c file; statically linking it with libbpf and common, dynamically linking it with libelf and libz
#clang -g -Wall -lelf -lz "$NAME".c common.c libbpf.a -o "$NAME"

# compiling the $NAME.c file; statically linking it with common, dynamically linking it with libbpf, libelf and libz
clang -g -Wall -lelf -lz "$NAME".c common.c -lbpf -o "$NAME"

# removing unnecessary $NAME.bpf.o (only useful for building the skeleton)
rm "$NAME".bpf.o
