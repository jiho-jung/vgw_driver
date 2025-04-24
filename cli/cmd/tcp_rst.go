package cmd

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/subchen/go-log"
	"golang.org/x/net/ipv4"
)

type VxlanInfo struct {
	Vni        uint32
	TunSrcIp   string
	TunDstIp   string
	TunDstPort uint16
}

type TcpInfo struct {
	SrcMAC  net.HardwareAddr
	DstMAC  net.HardwareAddr
	SrcIp   netip.Addr
	DstIp   netip.Addr
	SrcPort uint16
	DstPort uint16
	Id      uint32
	Seq     uint32
	Ack     uint32
}

func SendTcpReset(tcpInfo *TcpInfo, vxlanInfo *VxlanInfo) {

	if vxlanInfo != nil {
		/*
			log.Infof("## Send TCP Rst on Vxlan: %s:%d:%d={%s:%d:%d -> %s:%d:%d}",
				vxlanInfo.TunDstIp, vxlanInfo.TunDstPort, vxlanInfo.Vni,
				tcpInfo.SrcIp, tcpInfo.SrcPort, tcpInfo.Ack, tcpInfo.DstIp, tcpInfo.DstPort, tcpInfo.Seq)
		*/

		log.Infof("## VxLan Info: %+v", vxlanInfo)
	}

	//log.Infof("## Send TCP Rst: %s:%d:%d -> %s:%d:%d",
	//	tcpInfo.SrcIp, tcpInfo.SrcPort, tcpInfo.Ack, tcpInfo.DstIp, tcpInfo.DstPort, tcpInfo.Seq)

	log.Infof("## Send TCP Rst: %+v", tcpInfo)

	// ethernet header
	eth := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}
	_ = eth

	// ip header
	src := net.IP(tcpInfo.SrcIp.AsSlice())
	dst := net.IP(tcpInfo.DstIp.AsSlice())
	ip := layers.IPv4{
		SrcIP:    src,
		DstIP:    dst,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	// tcp header
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(tcpInfo.SrcPort),
		DstPort: layers.TCPPort(tcpInfo.DstPort),
		Urgent:  0,
		Seq:     tcpInfo.Seq,
		Ack:     tcpInfo.Ack,
		ACK:     false,
		SYN:     false,
		FIN:     false,
		RST:     true,
		URG:     true,
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

	pktBuf := gopacket.NewSerializeBuffer()

	if vxlanInfo == nil {
		eth.SrcMAC = tcpInfo.SrcMAC
		eth.DstMAC = tcpInfo.DstMAC
		// Ip packet
		err := gopacket.SerializeLayers(pktBuf, opts, &tcp)
		if err != nil {
			log.Errorf("failed to build tcp packet: err=%s", err)
			return
		}

		err = sendIpSocket(opts, &ip, pktBuf.Bytes())
		if err != nil {
			log.Errorf("failed to send tcp packet: err=%s", err)
		}

		return
	}

	err := gopacket.SerializeLayers(pktBuf, opts, &eth, &ip, &tcp)
	if err != nil {
		log.Errorf("failed to serialize packet: err=%s", err)
		return
	}

	// Vxlan
	err = sendVxlan(vxlanInfo, pktBuf.Bytes())
}

func sendVxlan(vxlanInfo *VxlanInfo, payload []byte) error {
	udpSock, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return err
	}
	defer udpSock.Close()

	vxlanHdr := []byte{0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	// set VNI
	binary.BigEndian.PutUint32(vxlanHdr[3:7], vxlanInfo.Vni)
	vxlanHdr[3] = 0

	// resolve UDP addr
	dst, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%v:%d", vxlanInfo.TunDstIp, vxlanInfo.TunDstPort))
	if err != nil {
		return err
	}

	vxlanHdr = append(vxlanHdr, payload...)
	fmt.Printf("vxlan payload: %v \n", vxlanHdr)

	_, err = udpSock.WriteTo(vxlanHdr, dst)

	return err
}

func sendIpSocket(opts gopacket.SerializeOptions, ip *layers.IPv4, payload []byte) error {
	ipHeaderBuf := gopacket.NewSerializeBuffer()
	err := ip.SerializeTo(ipHeaderBuf, opts)
	if err != nil {
		return err
	}

	ipHeader, err := ipv4.ParseHeader(ipHeaderBuf.Bytes())
	if err != nil {
		return err
	}

	_ = ipHeader

	// send packet
	var packetConn net.PacketConn
	var rawConn *ipv4.RawConn
	//packetConn, err = net.ListenPacket("ip4:tcp", "2.2.2.109")
	packetConn, err = net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return err
	}
	defer packetConn.Close()

	rawConn, err = ipv4.NewRawConn(packetConn)
	if err != nil {
		return err
	}
	defer rawConn.Close()

	err = rawConn.WriteTo(ipHeader, payload, nil)
	if err != nil {
		log.Printf("failed to send packet: err=%v !\n", err)
	} else {
		log.Printf("packet of length %d sent!\n", (len(payload) + len(ipHeaderBuf.Bytes())))
	}

	return nil
}

/*
func send_udp(data []byte,
	udpLayer *layers.UDP,
	ipv4Layer *layers.IPv4,
	ethernetLayer *layers.Ethernet,
	options gopacket.SerializeOptions,
) (err error) {

	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		udpLayer,
		gopacket.Payload(data),
	)

	return send_ipv4(buffer.Bytes(), ipv4Layer, ethernetLayer, options)
}

func send_ipv4(data []byte,
	ipv4Layer *layers.IPv4,
	ethernetLayer *layers.Ethernet,
	options gopacket.SerializeOptions,
) (err error) {

	buffer_ipv4 := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer_ipv4, options,
		ipv4Layer,
		gopacket.Payload(data),
	)
	return send_ethernet(buffer_ipv4.Bytes(), ethernetLayer, options)
}

func send_ethernet(data []byte,
	ethernetLayer *layers.Ethernet,
	options gopacket.SerializeOptions,
) (err error) {

	buffer_ethernet := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer_ethernet, options,
		ethernetLayer,
		gopacket.Payload(data),
	)

	err = handle.WritePacketData(buffer_ethernet.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	return err
}
*/
