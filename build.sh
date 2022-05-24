
if [ ! $# -eq 2 ]; then
  echo "usage: $0 <folder_name> <sample_name> (example: $0 map map_create)"
  exit 1
fi

FOLDER="$1"
SAMPLE_NAME="$2"
PREFIX="$FOLDER/$SAMPLE_NAME"
INCLUDES="./include"
LIBS="./lib"

set -e
set -x

# building the $SAMPLE.bpf.o BPF object file
clang -g -Wall -O2 -target bpf -c "$PREFIX.bpf.c" -o "$PREFIX.bpf.o"

# building the BPF skeleton
bpftool gen skeleton "$PREFIX.bpf.o" > "$PREFIX.skel.h"

# compiling the $NAME.c file; statically linking it with libbpf and common, dynamically linking it with libelf and libz
#clang -g -Wall -lelf -lz "$PREFIX.c" "$LIBS/common.c" "$LIBS/libbpf.a" -o "$PREFIX"

# compiling the $NAME.c file; statically linking it with common, dynamically linking it with libbpf, libelf and libz
clang -g -Wall -I"$INCLUDES/common.h" -I"$PREFIX.skel.h" \
  -lz "$PREFIX.c" "$LIBS/common.c" -lbpf -o "$PREFIX"

# removing unnecessary $NAME.bpf.o (only useful for building the skeleton)
rm "$PREFIX.bpf.o"

#
#
## building the $NAME.bpf.o BPF object file
#clang -g -Wall -O2 -target bpf -c "$NAME".bpf.c -o "$NAME".bpf.o
#
## building the BPF skeleton
#bpftool gen skeleton "$NAME".bpf.o > "$NAME".skel.h
#
## compiling the $NAME.c file; statically linking it with libbpf and common, dynamically linking it with libelf and libz
##clang -g -Wall -lelf -lz "$NAME".c common.c libbpf.a -o "$NAME"
#
## compiling the $NAME.c file; statically linking it with common, dynamically linking it with libbpf, libelf and libz
#clang -g -Wall -lelf -lz "$NAME".c common.c -lbpf -o "$NAME"
#
## removing unnecessary $NAME.bpf.o (only useful for building the skeleton)
#rm "$NAME".bpf.o
