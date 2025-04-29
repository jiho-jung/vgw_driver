//go:build linux

package bpf

import (
	"context"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type BpfLoader interface {
	Load(ctx context.Context) error
	Close()
}

func NewBpfLoader() (BpfLoader, error) {
	loader := &bpfLoader{}

	return loader, nil
}

///////////////////////////////

type bpfLoader struct {
	objs  *TcpBpfObjects
	links []link.Link
}

func (loader *bpfLoader) Load(ctx context.Context) error {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := &TcpBpfObjects{}
	if err := LoadTcpBpfObjects(objs, nil); err != nil {
		return fmt.Errorf("failed to load objects: err=%v", err)
	}

	loader.objs = objs
	err := addLink(loader, objs.OvsCtExecute)
	if err != nil {
		return err
	}

	return nil
}

func (loader *bpfLoader) Close() {
	for _, l := range loader.links {
		l.Close()
	}

	if loader.objs != nil {
		loader.objs.Close()
	}
}

func addLink(loader *bpfLoader, pg *ebpf.Program) error {
	lk, err := link.AttachTracing(link.TracingOptions{
		Program: pg,
	})

	if err != nil {
		return fmt.Errorf("failed to attach bpf: %s, err=%v", pg.String(), err)
	}

	loader.links = append(loader.links, lk)

	return nil
}
