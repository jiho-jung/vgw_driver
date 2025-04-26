BPF2GO_BIN=~/bin/bpf2go

all: $(BPF2GO_BIN)
	# use build.go without vendor mode causing an error
	#go generate
	
	${BPF2GO_BIN} -go-package bpf -target bpfel -cc clang -cflags "-O2 -g -Wall -Werror" TcpBpf ./src/tcp_track_bpf.c -- -I /home/jiho.jung/src/ebpf/examples/headers -I ./ -I /home/jiho.jung/linux-5.14.0-362.8.1.el9_3/tools/lib -I /home/jiho.jung/linux-5.14.0-362.8.1.el9_3/net/openvswitch

bin:
	make -C ../..

$(BPF2GO_BIN): 
	mkdir -p .tmp || true
	cd .tmp; git clone https://github.com/cilium/ebpf || true; cd ebpf/cmd/bpf2go; go build; cp bpf2go $(BPF2GO_BIN)
	rm -rf .tmp

