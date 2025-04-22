package cmd

// https://github.com/a-zaki/genl_ex/blob/master/genl_ex.c
// https://github.com/mdlayher/wifi/tree/main

import (
	"errors"
	"fmt"
	"os"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/subchen/go-log"
	"github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"
)

var cmdNetlink = &cobra.Command{
	Use:     "netlink",
	Aliases: []string{"nl"},
	Short:   "Kernel netlink",
	Long:    `Kernel netlink `,
}

var cmdGeneralShow = &cobra.Command{
	Use:     "show",
	Aliases: []string{"sh"},
	Short:   "show conntrack",
	Run:     runGenShow,
}

func init() {
	cmdNetlink.PersistentFlags().IntP("zone", "z", -1, "zone id, -1: use cli parameter, >=0: use ct")
	viper.BindPFlag("zone", cmdNetlink.PersistentFlags().Lookup("zone"))

	cmdNetlink.AddCommand(cmdGeneralShow)

	// ct root cmd
	RootCmd.AddCommand(cmdNetlink)
}

/*
func marshalAttrs(attrs []netlink.Attribute) []byte {
	b, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal attributes: %v", err))
	}

	return b
}
*/

/*
// encodeAttributes encodes a list of Attributes into the given netlink.AttributeEncoder.
func encodeAttributes(ae *netlink.AttributeEncoder, attrs []Attribute) error {
	if ae == nil {
		return errNilAttributeEncoder
	}

	attr := netlink.Attribute{}
	return attr.encode(attrs)(ae)
}

// MarshalNetlink takes a Netfilter Header and Attributes and returns a netlink.Message.
func MarshalNetlink(h Header, attrs []Attribute) (netlink.Message, error) {
	ae := netlink.NewAttributeEncoder()
	if err := encodeAttributes(ae, attrs); err != nil {
		return netlink.Message{}, err
	}

	return EncodeNetlink(h, ae)
}
*/

const Protocol = 0x10 // unix.NETLINK_GENERIC

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

func runGenShow(cmd *cobra.Command, args []string) {
	log.Debugf("Show Conntracks by netlink")

	c, err := DialNetlink(nil)
	if err != nil {
		fmt.Printf("failed to dial netlink: %v\n", err)
		return
	}
	defer c.Close()

	vgwnl := genetlink.NewConn(c)
	/*
		vgwnl, err := genetlink.Dial(nil)
		if err != nil {
			fmt.Printf("failed to dial generic netlink: %v\n", err)
			return
		}

		defer vgwnl.Close()
	*/

	const name = "vgw_nl_ct"
	family, err := vgwnl.GetFamily(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Printf("%q family not available \n", name)
			return
		}

		fmt.Printf("failed to query for family: %v \n", err)
		return
	}

	fmt.Printf("general name=%s: %+v \n", name, family)

	var zone uint32
	zone = 100

	/*
		var f *conntrack.FilterZone
		f = &conntrack.FilterZone{
			Zone: uint16(100),
		}

		DumpFilter(vgwnl, family.ID, f, nil)
	*/

	enc := netlink.NewAttributeEncoder()
	//var attrs []netlink.Attribute

	if zone != 0 {
		/*
			attrs = append(attrs,
				netlink.Attribute{
					Type: 1, // VGW_NL_CT_ATTR_ZONE
					Data: netfilter.Uint32Bytes(zone),
				})
		*/

		enc.Uint32(1, zone)
	}

	/*
		attrs = append(attrs, netlink.Attribute{
			Type: 1,
			Data: []byte("12345678"),
		})
	*/

	req := genetlink.Message{
		Header: genetlink.Header{
			Command: 1, // VGW_NL_CT_CMD_DUMP
		},
	}

	//req.Data = marshalAttrs(attrs)
	req.Data, err = enc.Encode()

	////////////////////////
	//retMsg, err := gen.Execute(req, family.ID, netlink.Request|netlink.Dump)
	retMsg, err := vgwnl.Execute(req, family.ID, netlink.Request)
	if err != nil {
		fmt.Printf("failed to execute: %v \n", err)
		return
	}
	fmt.Printf("1. General Msg:type=%T, %+v \n", retMsg, retMsg)

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

	for _, gmsg := range retMsg1 {
		ad, err := netlink.NewAttributeDecoder(gmsg.Data[:])
		if err != nil {
			fmt.Printf("failed to new decoder: err=%v", err)
			return
		}

		// All Netfilter attribute payloads are big-endian. (network byte order)
		//ad.ByteOrder = binary.BigEndian

		for ad.Next() {
			t := ad.Type()
			fmt.Printf("Attr.Type=%d, string=%s \n", t, ad.String())
		}
	}

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

func DumpFilter(vgwnl *genetlink.Conn, familyId uint16, f *conntrack.FilterZone, opts *conntrack.DumpOptions) ([]conntrack.Flow, error) {
	var attrs []netfilter.Attribute
	if !conntrack.IsNil(f) {
		attrs = f.Marshal()
	}

	//msgType := ctGet
	msgType := 1
	/*
		if opts != nil && opts.ZeroCounters {
			msgType = ctGetCtrZero
		}
	*/

	nfReq, err := netfilter.MarshalNetlink(
		netfilter.Header{
			SubsystemID: netfilter.NFSubsysCTNetlink,
			MessageType: netfilter.MessageType(msgType),
			Family:      netfilter.ProtoUnspec, // ProtoUnspec dumps both IPv4 and IPv6
			Flags:       netlink.Request | netlink.Dump,
		}, attrs)
	if err != nil {
		return nil, err
	}

	genReq := genetlink.Message{
		Header: genetlink.Header{
			//Command: nl80211CommandGetInterface,
			//Version: family.Version,
			Command: 1,
			Version: 1,
		},
	}

	data, err := nfReq.MarshalBinary()
	if err != nil {
		return nil, err
	}
	genReq.Data = data

	msgs, err := vgwnl.Execute(genReq, familyId, netlink.Request|netlink.Dump)
	if err != nil {
		log.Fatalf("failed to execute: %v", err)
	}
	_ = msgs

	/*
		nlm, err := c.Query(req)
		nlm, err := c.Execute(nfReq)
		if err != nil {
			return nil, err
		}
	*/

	//return unmarshalFlows(nlm)

	return nil, nil
}
