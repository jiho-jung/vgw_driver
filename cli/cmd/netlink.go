package cmd

// https://github.com/a-zaki/genl_ex/blob/master/genl_ex.c
// https://github.com/mdlayher/wifi/tree/main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"

	"github.com/josharian/native"
	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	VGW_NETLINK_NAME = "vgw_nl_ct"
	Protocol         = 0x10 // unix.NETLINK_GENERIC
)

const (
	FltUnspec uint16 = iota
	FltAttrFilter
	FltAttrTcpSeq
)

const (
	CmdUnspec uint8 = iota
	CmdDump
)

type TcpSeqFilter struct {
	Id       uint32
	Zone     uint32
	SrcIp    uint32
	DstIp    uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	Dummy    [3]uint8
}

type TcpSeq struct {
	Id  uint32 // Id in conntrack
	Seq uint32
	Ack uint32
}

type VgatewayNetlinkConn struct {
	Conn *genetlink.Conn
	Id   uint16
}

func (f *TcpSeq) UnMarshal(b []byte) error {
	f.Id = native.Endian.Uint32(b[0:])
	f.Seq = native.Endian.Uint32(b[4:])
	f.Ack = native.Endian.Uint32(b[8:])

	return nil
}

func (f *TcpSeqFilter) Marshal() []byte {
	var n int
	b := make([]byte, 24)

	native.Endian.PutUint32(b[n:], f.Id)
	n += 4
	native.Endian.PutUint32(b[n:], f.Zone)
	n += 4
	native.Endian.PutUint32(b[n:], f.SrcIp)
	n += 4
	native.Endian.PutUint32(b[n:], f.DstIp)
	n += 4
	native.Endian.PutUint16(b[n:], f.SrcPort)
	n += 2
	native.Endian.PutUint16(b[n:], f.DstPort)
	n += 2
	b[n] = f.Protocol
	n += 1
	b[n] = f.Dummy[0]
	n += 1
	b[n] = f.Dummy[1]
	n += 1
	b[n] = f.Dummy[2]
	n += 1

	return b
}

func (c *VgatewayNetlinkConn) Close() {
	c.Conn.Close()
}

func Ipv4ToUint32(addr netip.Addr) uint32 {
	s := addr.AsSlice()
	return binary.BigEndian.Uint32(s)
}

func ConnectVgatewayNetlink() (conn *VgatewayNetlinkConn, err error) {
	nl, err := genetlink.Dial(nil)
	if err != nil {
		err = fmt.Errorf("failed to dial generic netlink: %v", err)
		return nil, err
	}

	defer func() {
		if err != nil {
			nl.Close()
		}
	}()

	family, err := nl.GetFamily(VGW_NETLINK_NAME)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			err = fmt.Errorf("%s family not available", VGW_NETLINK_NAME)
			return nil, err
		}

		err = fmt.Errorf("failed to query for %s family: %v", VGW_NETLINK_NAME, err)
		return nil, err
	}

	fmt.Printf("general netlink: %s: %+v", VGW_NETLINK_NAME, family)

	return &VgatewayNetlinkConn{
		Conn: nl,
		Id:   family.ID,
	}, nil
}

func GetTcpSeq(conn *VgatewayNetlinkConn, zone uint32, tcpinfo *TcpInfo) ([]TcpSeq, error) {
	var err error
	var flt TcpSeqFilter

	flt.Id = tcpinfo.Id
	flt.Zone = zone
	flt.DstIp = Ipv4ToUint32(tcpinfo.SrcIp)
	flt.SrcIp = Ipv4ToUint32(tcpinfo.DstIp)
	flt.SrcPort = tcpinfo.DstPort
	flt.DstPort = tcpinfo.SrcPort
	//flt.Protocol = 6
	flt.Protocol = unix.IPPROTO_TCP

	b := flt.Marshal()
	t := uint16(FltAttrFilter)
	fmt.Printf("tcp filter: %+v \n", flt)

	// generate netlink attributes
	enc := netlink.NewAttributeEncoder()
	enc.Bytes(t, b)

	req := genetlink.Message{
		Header: genetlink.Header{
			Command: CmdDump,
		},
	}

	req.Data, err = enc.Encode()

	retMsg, err := conn.Conn.Execute(req, conn.Id, netlink.Request)
	if err != nil {
		err = fmt.Errorf("failed to execute: %v", err)
		return nil, err
	}
	fmt.Printf("General Msg:type=%T, %+v \n", retMsg, retMsg)

	/*
		////////////////////////
		nm, err := packMessage(req, family.ID, netlink.Request)
		msgs, err := c.Execute(nm)
		if err != nil {
			fmt.Printf("failed to execute: %v \n", err)
			return
		}
		fmt.Printf("2. Netlink Msg:type=%T, %+v \n", msgs, msgs)

		retMsg1, err := unpackMessages(msgs)
		fmt.Printf("3. General Msg:type=%T, %+v \n", retMsg1, retMsg1)
	*/

	tcpseq := UnpackMessage(retMsg)

	return tcpseq, nil
}

func UnpackMessage(msgs []genetlink.Message) []TcpSeq {
	var tcpseq []TcpSeq

	for _, gmsg := range msgs {
		ad, err := netlink.NewAttributeDecoder(gmsg.Data[:])
		if err != nil {
			fmt.Printf("failed to new decoder: err=%v", err)
			continue
		}

		for ad.Next() {
			switch ad.Type() {
			case FltAttrTcpSeq:
				b := ad.Bytes()
				var res TcpSeq
				if err := res.UnMarshal(b); err != nil {
					fmt.Printf("failed to unmarshal: err=%v", err)
				} else {
					tcpseq = append(tcpseq, res)
				}
			default:
				fmt.Printf("unknown object type=%v\n", ad.Type())
			}
		}
	}

	return tcpseq
}

/*
// Dial dials a generic netlink connection.  Config specifies optional
// configuration for the underlying netlink connection.  If config is
// nil, a default configuration will be used.
func DialNetlink(config *netlink.Config) (*netlink.Conn, error) {
	c, err := netlink.Dial(Protocol, config)
	if err != nil {
		return nil, err
	}

	return c, nil
}

// packMessage packs a generic netlink Message into a netlink.Message with the
// appropriate generic netlink family and netlink flags.
func packMessage(m genetlink.Message, family uint16, flags netlink.HeaderFlags) (netlink.Message, error) {
	nm := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(family),
			Flags: flags,
		},
	}

	mb, err := m.MarshalBinary()
	if err != nil {
		return netlink.Message{}, err
	}
	nm.Data = mb

	return nm, nil
}

// unpackMessages unpacks generic netlink Messages from a slice of netlink.Messages.
func unpackMessages(msgs []netlink.Message) ([]genetlink.Message, error) {
	gmsgs := make([]genetlink.Message, 0, len(msgs))
	for _, nm := range msgs {
		var gm genetlink.Message
		if err := (&gm).UnmarshalBinary(nm.Data); err != nil {
			return nil, err
		}

		gmsgs = append(gmsgs, gm)
	}

	return gmsgs, nil
}
*/
