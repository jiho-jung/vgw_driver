//go:build linux

package bpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type BpfLoader struct {
	objs  *TcpBpfObjects
	links []link.Link
}

func (loader *BpfLoader) Close() {
	for _, l := range loader.links {
		l.Close()
	}

	if loader.objs != nil {
		loader.objs.Close()
	}
}

func NewBpfLoader() (*BpfLoader, error) {
	loader := &BpfLoader{}

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return loader, err
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := &TcpBpfObjects{}
	if err := LoadTcpBpfObjects(objs, nil); err != nil {
		return loader, fmt.Errorf("loading objects: %v", err)
	}

	loader.objs = objs

	addLink(loader, objs.OvsCtExecute)

	return loader, nil
}

func addLink(loader *BpfLoader, pg *ebpf.Program) error {
	lk, err := link.AttachTracing(link.TracingOptions{
		Program: pg,
	})

	if err != nil {
		return fmt.Errorf("failed to attach bpf: %s, err=%v", pg.String(), err)
	}

	loader.links = append(loader.links, lk)

	return nil
}
