all: gen
	make -C ../

gen:
	#go generate
	#//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" bpf tcp_ct_bpf.c -- -I /home/jiho.jung/src/ebpf/examples/headers -I ./ -I /home/jiho.jung/linux-5.14.0-362.8.1.el9_3/tools/lib -I /home/jiho.jung/linux-5.14.0-362.8.1.el9_3/net/openvswitch

	go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" bpf tcp_ct_bpf.c -- -I /home/jiho.jung/src/ebpf/examples/headers -I ./ -I /home/jiho.jung/linux-5.14.0-362.8.1.el9_3/tools/lib -I /home/jiho.jung/linux-5.14.0-362.8.1.el9_3/net/openvswitch
