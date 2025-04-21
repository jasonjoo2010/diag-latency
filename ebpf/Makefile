all: skb.o

generate:
	export BPF_CLANG=clang; \
	export BPF_CFLAGS="-O2 -g -Wall -Werror -D__TARGET_ARCH_x86"; \
	cd ../gobpf && go generate ./...

skb.o: skb.c
	clang \
		-target bpf \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-D__TARGET_ARCH_x86 \
		-g \
		-O2 -c $< -o $@
	llvm-strip -g $@
