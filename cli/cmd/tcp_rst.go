package cmd

import (
	"net"
	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/subchen/go-log"
	"golang.org/x/net/ipv4"
)

func SendTcpReset(srcIp netip.Addr, dstIp netip.Addr, srcPort uint16, dstPort uint16, seq uint32, ack uint32) {
	log.Infof("## Send TCP Rst: %s:%d:%d -> %s:%d:%d",
		srcIp, srcPort, ack,
		dstIp, dstPort, seq)

	src := net.IP(srcIp.AsSlice())
	dst := net.IP(dstIp.AsSlice())

	ip := layers.IPv4{
		SrcIP:    src,
		DstIP:    dst,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Urgent:  0,
		Seq:     seq,
		Ack:     ack,
		ACK:     true,
		SYN:     false,
		FIN:     false,
		RST:     true,
		URG:     false,
		ECE:     false,
		CWR:     false,
		NS:      false,
		PSH:     false,
	}

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	tcp.SetNetworkLayerForChecksum(&ip)

	ipHeaderBuf := gopacket.NewSerializeBuffer()
	err := ip.SerializeTo(ipHeaderBuf, opts)
	if err != nil {
		panic(err)
	}
	ipHeader, err := ipv4.ParseHeader(ipHeaderBuf.Bytes())
	if err != nil {
		panic(err)
	}

	tcpPayloadBuf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(tcpPayloadBuf, opts, &tcp)
	if err != nil {
		log.Errorf("failed to build tcp packet: err=%s", err)
		return
	}

	// send packet
	var packetConn net.PacketConn
	var rawConn *ipv4.RawConn
	//packetConn, err = net.ListenPacket("ip4:tcp", "2.2.2.109")
	packetConn, err = net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		panic(err)
	}
	rawConn, err = ipv4.NewRawConn(packetConn)
	if err != nil {
		panic(err)
	}

	err = rawConn.WriteTo(ipHeader, tcpPayloadBuf.Bytes(), nil)

	log.Printf("packet of length %d sent!\n", (len(tcpPayloadBuf.Bytes()) + len(ipHeaderBuf.Bytes())))
}
