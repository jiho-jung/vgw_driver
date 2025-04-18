//go:build linux

// This program demonstrates attaching a fentry eBPF program to
// tcp_close and reading the RTT from the TCP socket using CO-RE helpers.
// It prints the IPs/ports/RTT information
// once the host closes a TCP connection.
// It supports only IPv4 for this example.
//
// Sample output:
//
// examples# go run -exec sudo ./tcprtt
// 2022/03/19 22:30:34 Src addr        Port   -> Dest addr       Port   RTT
// 2022/03/19 22:30:36 10.0.1.205      50578  -> 117.102.109.186 5201   195
// 2022/03/19 22:30:53 10.0.1.205      0      -> 89.84.1.178     9200   30
// 2022/03/19 22:30:53 10.0.1.205      36022  -> 89.84.1.178     9200   28
package cmd

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" bpf tcp_ct_bpf.c -- -I /home/jiho.jung/src/ebpf/examples/headers -I ./ -I /home/jiho.jung/linux-5.14.0-362.8.1.el9_3/tools/lib -I /home/jiho.jung/linux-5.14.0-362.8.1.el9_3/net/openvswitch

type VgwBpf struct {
	objs  *bpfObjects
	links []link.Link
}

func (vgwBpf *VgwBpf) Close() {
	fmt.Printf("Close link \n")
	for _, l := range vgwBpf.links {
		l.Close()
	}

	if vgwBpf.objs != nil {
		vgwBpf.objs.Close()
	}
}

func LoadBpf() (*VgwBpf, error) {
	vgwBpf := &VgwBpf{}

	fmt.Printf("Load bpf \n")

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return vgwBpf, err
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := &bpfObjects{}
	if err := loadBpfObjects(objs, nil); err != nil {
		return vgwBpf, fmt.Errorf("loading objects: %v", err)
	}

	vgwBpf.objs = objs

	// see the pkt twice
	addLink(vgwBpf, objs.OvsCtExecute)

	return vgwBpf, nil
}

func addLink(vgwBpf *VgwBpf, pg *ebpf.Program) error {
	lk, err := link.AttachTracing(link.TracingOptions{
		Program: pg,
	})

	if err != nil {
		return fmt.Errorf("failed to attach bpf: %s, err=%v", pg.String(), err)
	}

	vgwBpf.links = append(vgwBpf.links, lk)

	return nil
}
