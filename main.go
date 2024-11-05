package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const (
	TYPE_ENTER = 1
	TYPE_DROP  = 2
	TYPE_PASS  = 3
)

type event struct {
	TimeSinceBoot  uint64
	ProcessingTime uint32
	Type           uint8
}

func main() {
	spec, err := ebpf.LoadCollectionSpec("ebpf.o")
	if err != nil {
		panic(err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		panic(err)
	}
	defer coll.Close()

	prog := coll.Programs["count_packets"]
	if prog == nil {
		panic("no count_packets program found")
	}

	iface, err := net.InterfaceByName("eth0")
	if err != nil {
		panic(err)
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
	})
	if err != nil {
		panic(err)
	}
	defer link.Close()

	fmt.Println("Attached XDP program to eth0")

	pktCountMap := coll.Maps["pkt_count"]
	var key uint32
	var value uint64

	go func() {
		for {
			err := pktCountMap.Lookup(&key, &value)
			if err != nil {
				panic(err)
			}

			fmt.Printf("Packet count: %d\n", value)
			time.Sleep(1 * time.Second)
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
}
