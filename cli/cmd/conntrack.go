package cmd

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/netip"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/subchen/go-log"
	"github.com/ti-mo/conntrack"
)

var cmdCt = &cobra.Command{
	Use:     "conntrack",
	Aliases: []string{"ct"},
	Short:   "Kernel conntrack",
	Long:    `Kernel Conntrack `,
}

var cmdCtShow = &cobra.Command{
	Use:     "show",
	Aliases: []string{"sh"},
	Short:   "show conntracks",
	Run:     runCmdCtShow,
}

var cmdCtFlush = &cobra.Command{
	Use:     "flush",
	Aliases: []string{"fh"},
	Short:   "flush conntracks",
	Run:     runCmdCtFlush,
}

var cmdCtAdd = &cobra.Command{
	Use:   "add",
	Short: "add conntracks",
	Run:   runCmdCtAdd,
}

var cmdCtReset = &cobra.Command{
	Use:   "reset",
	Short: "reset conntracks",
	Run:   runCmdCtReset,
}

var cmdCtTrackTcp = &cobra.Command{
	Use:   "track",
	Short: "track tcp seq/ack",
	Run:   runCmdCtTrackTcp,
}

func init() {
	cmdCt.PersistentFlags().IntP("zone", "z", -1, "zone id, -1: use cli parameter, >=0: use ct")
	viper.BindPFlag("zone", cmdCt.PersistentFlags().Lookup("zone"))

	cmdCt.AddCommand(cmdCtShow)

	cmdCt.AddCommand(cmdCtFlush)

	cmdCt.AddCommand(cmdCtAdd)

	// vxlan info
	cmdCtReset.Flags().Uint32P("vni", "", 0, "VXLAN ID: >0: use vxlan tunnel")
	cmdCtReset.Flags().StringP("tundst", "", "", "tunnel dest ip")
	cmdCtReset.Flags().StringP("tunsrc", "", "", "tunnel src ip")
	cmdCtReset.Flags().Uint16P("tunport", "", 4789, "tunnel dst port")

	// inner tcp info
	cmdCtReset.Flags().StringP("smac", "", "", "inner src MAC addr")
	cmdCtReset.Flags().StringP("dmac", "", "", "inner dst MAC addr")
	cmdCtReset.Flags().StringP("sip", "", "", "inner src ip")
	cmdCtReset.Flags().StringP("dip", "", "", "inner dest ip")
	cmdCtReset.Flags().Uint16P("sport", "", 0, "src port")
	cmdCtReset.Flags().Uint16P("dport", "", 0, "dst port")
	cmdCtReset.Flags().Uint32P("seq", "", 0, "seq number")
	cmdCtReset.Flags().Uint32P("ack", "", 0, "ack number")

	if err := viper.BindPFlags(cmdCtReset.Flags()); err != nil {
		log.Errorf("failed to dump p-flags: %v", err)
	}
	cmdCt.AddCommand(cmdCtReset)

	cmdCtTrackTcp.Flags().IntP("value", "", -1, "set track tcp seq/ack, -1: show")
	if err := viper.BindPFlags(cmdCtTrackTcp.Flags()); err != nil {
		log.Errorf("failed to dump p-flags: %v", err)
	}
	cmdCt.AddCommand(cmdCtTrackTcp)

	// ct root cmd
	RootCmd.AddCommand(cmdCt)
}

func runCmdCtReset(cmd *cobra.Command, args []string) {
	log.Debugf("Reset Conntracks")

	vni := viper.GetUint32("vni")
	zone := viper.GetInt("zone")

	var err error
	var tcpInfo *TcpInfo
	var vxlanInfo *VxlanInfo

	if vni != 0 {
		vxlanInfo, err = getVxLanInfo()
		if err != nil {
			log.Errorf("faled to get vxlaninfo: err=%v", err)
			return
		}
	}

	if zone == -1 {
		tcpInfo, err = getTcpInfo()
		if err != nil {
			log.Errorf("failed to get tcpinfo: err=%v", err)
			return
		}
	} else {
		tcpInfo, err = getConntrack(zone)
		if err != nil {
			log.Errorf("failed to get ct: err=%v", err)
			return
		}
	}

	if tcpInfo == nil {
		log.Errorf("no TcpInfo")
		return
	}

	err = getInnerMac(tcpInfo)
	if err != nil {
		log.Errorf("failed to get inner mac: err=%v", err)
		return
	}

	SendTcpReset(tcpInfo, vxlanInfo)
}

func getTcpInfo() (*TcpInfo, error) {
	sip := viper.GetString("sip")
	dip := viper.GetString("dip")
	sport := viper.GetUint16("sport")
	dport := viper.GetUint16("dport")

	seq := viper.GetUint32("seq")
	ack := viper.GetUint32("ack")

	if len(sip) < 1 {
		return nil, fmt.Errorf("src ip needed")
	}

	saddr, err := netip.ParseAddr(sip)
	if err != nil {
		return nil, err
	}

	if len(dip) < 1 {
		return nil, fmt.Errorf("dst ip needed")
	}

	daddr, err := netip.ParseAddr(dip)
	if err != nil {
		return nil, err
	}

	tcpInfo := &TcpInfo{
		SrcIp:   saddr,
		DstIp:   daddr,
		SrcPort: sport,
		DstPort: dport,
		Seq:     seq,
		Ack:     ack,
	}

	return tcpInfo, nil
}

func getVxLanInfo() (*VxlanInfo, error) {
	vni := viper.GetUint32("vni")
	tunport := viper.GetUint16("tunport")
	tundst := viper.GetString("tundst")
	tunsrc := viper.GetString("tunsrc")

	var vxlanInfo *VxlanInfo
	if vni == 0 {
		return nil, nil
	}

	if len(tundst) < 1 {
		return nil, fmt.Errorf("Tunnel dst IP is needed: vni=%d", vni)
	}

	if len(tunsrc) < 1 {
		return nil, fmt.Errorf("Tunnel src IP is needed: vni=%d", vni)
	}

	vxlanInfo = &VxlanInfo{
		Vni:        uint32(vni),
		TunSrcIp:   tunsrc,
		TunDstIp:   tundst,
		TunDstPort: uint16(tunport),
	}

	return vxlanInfo, nil
}

func getInnerMac(tcpInfo *TcpInfo) error {
	smac := viper.GetString("smac")
	dmac := viper.GetString("smac")

	if len(smac) > 1 {
		smacAddr, err := net.ParseMAC(smac)
		if err != nil {
			return fmt.Errorf("failed to parse SDMAC: err=%v", err)
		} else {
			tcpInfo.SrcMAC = smacAddr
		}
	}

	if len(dmac) > 1 {
		dmacAddr, err := net.ParseMAC(dmac)
		if err != nil {
			return fmt.Errorf("failed to parse DDMAC: err=%v", err)
		} else {
			tcpInfo.DstMAC = dmacAddr
		}
	}

	return nil
}

func getConntrack(zone int) (*TcpInfo, error) {
	sport := viper.GetUint16("sport")
	dport := viper.GetUint16("dport")

	c, err := conntrack.Dial(nil)
	if err != nil {
		return nil, err
	}

	var f *conntrack.FilterZone
	f = &conntrack.FilterZone{
		Zone: uint16(zone),
	}

	cts, err := c.DumpFilter(f, nil)
	if err != nil {
		return nil, err
	}

	var tcpInfo *TcpInfo

	var i int
	for _, ct := range cts {
		if ct.ProtoInfo.TCP == nil {
			continue
		} else if ct.TupleOrig.Proto.Protocol != 6 {
			continue
		} else if sport != 0 && ct.TupleOrig.Proto.SourcePort != sport {
			continue
		} else if dport != 0 && ct.TupleOrig.Proto.DestinationPort != dport {
			continue
		}

		fmt.Printf("CT(%d): %+v \n", i+1, ct)
		fmt.Printf("  TCP: %+v \n", *ct.ProtoInfo.TCP)

		if ct.ProtoInfo.TCP.SeqTrack != nil {
			fmt.Printf("  TCP SEQ: %+v \n", *ct.ProtoInfo.TCP.SeqTrack)
			//tcpReset(&ct, vxlanInfo)

			tuple := &ct.TupleOrig
			seqTrk := ct.ProtoInfo.TCP.SeqTrack

			tcpInfo = &TcpInfo{
				SrcIp:   tuple.IP.DestinationAddress,
				DstIp:   tuple.IP.SourceAddress,
				SrcPort: tuple.Proto.DestinationPort,
				DstPort: tuple.Proto.SourcePort,
				Seq:     seqTrk.LastAck,
				Ack:     seqTrk.LastSeq,
			}

			break
		}
	}

	return tcpInfo, nil
}

func tcpReset(ct *conntrack.Flow, vxlanInfo *VxlanInfo) {
	tuple := &ct.TupleOrig
	seqTrk := ct.ProtoInfo.TCP.SeqTrack

	tcpInfo := TcpInfo{
		SrcIp:   tuple.IP.DestinationAddress,
		DstIp:   tuple.IP.SourceAddress,
		SrcPort: tuple.Proto.DestinationPort,
		DstPort: tuple.Proto.SourcePort,
		Seq:     seqTrk.LastAck,
		Ack:     seqTrk.LastSeq,
	}

	SendTcpReset(&tcpInfo, vxlanInfo)
}

func runCmdCtShow(cmd *cobra.Command, args []string) {
	log.Debugf("Show Conntracks")

	//OpenFlowListenAddr: viper.GetString(KeyOpenFlowListenAddr),
	zone := viper.GetInt("zone")

	c, err := conntrack.Dial(nil)
	if err != nil {
		log.Errorf("1. %s", err)
		return
	}

	var f *conntrack.FilterZone
	if zone != -1 {
		f = &conntrack.FilterZone{
			Zone: uint16(zone),
		}
	}

	cts, err := c.DumpFilter(f, nil)
	if err != nil {
		log.Errorf("2. %s", err)
		return
	}

	var i int
	for _, ct := range cts {
		fmt.Printf("CT(%d): %+v \n", i+1, ct)
		if ct.ProtoInfo.TCP != nil {
			fmt.Printf("  TCP: %+v \n", *ct.ProtoInfo.TCP)
			if ct.ProtoInfo.TCP.SeqTrack != nil {
				fmt.Printf("  TCP SEQ: %+v \n", *ct.ProtoInfo.TCP.SeqTrack)
			}
		}
	}
}

func runCmdCtAdd(cmd *cobra.Command, args []string) {
	log.Debugf("Add Conntracks")

	c, err := conntrack.Dial(nil)
	if err != nil {
		log.Errorf("failed to add ct: err=%v", err)
		return
	}

	zone := viper.GetInt("zone")
	if zone == -1 {
		zone = 0
	}

	for srcPort := 1; srcPort <= 1; srcPort++ {
		f1 := conntrack.NewFlow(
			6, 0, netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8"),
			uint16(srcPort), 80, 120, 0x00ff, // Set a connection mark
		)

		f1.Zone = uint16(zone)
		err := c.Create(f1)
		if err != nil {
			log.Errorf("failed to create ct: zone=%d, err=%v", zone, err)
		} else {
			//log.Debugf("### added: %+v", f1)
		}
	}
}

func runCmdCtFlush(cmd *cobra.Command, args []string) {
	log.Debugf("Flush Conntracks")

	zone := viper.GetInt("zone")
	var f *conntrack.FilterZone
	if zone != -1 {
		f = &conntrack.FilterZone{
			Zone: uint16(zone),
		}
	}

	// Open a Conntrack connection.
	c, err := conntrack.Dial(nil)
	if err != nil {
		log.Errorf("failed to flush ct: err=%v", err)
		return
	}

	// Evict all entries from the conntrack table in the current network namespace.
	err = c.FlushFilter(f)
	if err != nil {
		log.Errorf("failed to flush ct with filter: err=%v", err)
		return
	}
}

func runCmdCtTrackTcp(cmd *cobra.Command, args []string) {
	log.Debugf("Set Track TCP SEQ/ACK")

	fname := "/sys/module/vgw_driver/parameters/enable_tcptrack"
	value := viper.GetInt("value")

	if value == -1 {
		v, err := readSysfs(fname)
		if err != nil {
			log.Errorf("failed to read fs: filename=%s, err=%v", fname, err)
			return
		}

		fmt.Printf("%s:%s \n", fname, v)
	} else if value == 1 {
		err := writeSysfs(fname, "1")
		if err != nil {
			log.Errorf("failed to write fs: filename=%s, err=%v", fname, err)
			return
		}
	} else if value == 0 {
		err := writeSysfs(fname, "0")
		if err != nil {
			log.Errorf("failed to write fs: filename=%s, err=%v", fname, err)
			return
		}
	} else {
		log.Errorf("not supported value: value=%d", value)
	}
}

func writeSysfs(filename string, data string) error {
	return ioutil.WriteFile(filename, []byte(data), 644)
}

func readSysfs(filename string) (string, error) {
	byts, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	}

	return string(byts), nil
}
