package cmd

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/subchen/go-log"
	"github.com/ti-mo/conntrack"
)

var paramZone int

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

var cmdCtTrackFlag = &cobra.Command{
	Use:   "track",
	Short: "track flags",
	Run:   runCmdCtTrackFlag,
}

func init() {
	//cmdCt.PersistentFlags().IntP("zone", "z", -1, "zone id, -1: use cli parameter, >=0: use ct")
	cmdCt.PersistentFlags().IntVarP(&paramZone, "zone", "z", 0, "zone")
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

	cmdCtTrackFlag.Flags().IntP("tcp-track", "", -1, "tcp track")
	cmdCtTrackFlag.Flags().IntP("zone-filter", "", -1, "zonefilter")
	cmdCtTrackFlag.Flags().IntP("export-tcp-track", "", -1, "export tcp track info")
	cmdCtTrackFlag.Flags().IntP("dump-pkt", "", -1, "dump pkt")

	if err := viper.BindPFlags(cmdCtTrackFlag.Flags()); err != nil {
		log.Errorf("failed to dump p-flags: %v", err)
	}
	cmdCt.AddCommand(cmdCtTrackFlag)

	// ct root cmd
	RootCmd.AddCommand(cmdCt)
}

func runCmdCtReset(cmd *cobra.Command, args []string) {
	log.Debugf("Reset Conntracks")

	vni := viper.GetUint32("vni")
	zone := paramZone
	log.Debugf("Zone=%d", zone)

	var err error
	var tcpInfo *TcpInfo
	var tcpInfo1 *TcpInfo = &TcpInfo{}
	var vxlanInfo *VxlanInfo

	if vni != 0 {
		vxlanInfo, err = getVxLanInfo()
		if err != nil {
			log.Errorf("faled to get vxlaninfo: err=%v", err)
			return
		}
	}

	if zone == -1 {
		tcpInfo, err = GetTcpInfoFromCli()
		if err != nil {
			log.Errorf("failed to get tcpinfo: err=%v", err)
			return
		}
	} else {
		sport := viper.GetUint16("sport")
		dport := viper.GetUint16("dport")

		c, err := conntrack.Dial(nil)
		if err != nil {
			log.Errorf("failed to connect netlink: err=%v", err)
			return
		}
		defer c.Close()

		tcpInfo, err = GetTcpInfoFromConntrack(c, uint32(zone), sport, dport)
		if err != nil {
			log.Errorf("failed to get ct: err=%v", err)
			return
		}
	}

	if tcpInfo == nil {
		log.Errorf("No TcpInfo")
		return
	}

	fmt.Printf("TCPInfo: %+v \n", tcpInfo)

	err = getInnerMac(tcpInfo)
	if err != nil {
		log.Errorf("failed to get inner mac: err=%v", err)
		return
	}

	/*
		// XXXX: need arp for server and client in NLB host
		sudo arp -s 3.3.3.11 52:54:88:88:89:0b
		sudo arp -s 3.3.3.21 52:54:88:88:89:15
	*/

	tcpInfo1.SrcMAC, _ = net.ParseMAC(tcpInfo.DstMAC.String())
	tcpInfo1.DstMAC, _ = net.ParseMAC(tcpInfo.SrcMAC.String())
	tcpInfo1.SrcIp, _ = netip.ParseAddr(tcpInfo.DstIp.String())
	tcpInfo1.DstIp, _ = netip.ParseAddr(tcpInfo.SrcIp.String())
	tcpInfo1.SrcPort = tcpInfo.DstPort
	tcpInfo1.DstPort = tcpInfo.SrcPort
	tcpInfo1.Seq = tcpInfo.Ack
	tcpInfo1.Ack = tcpInfo.Seq

	SendTcpReset(tcpInfo, vxlanInfo)
	SendTcpReset(tcpInfo1, vxlanInfo)
}

func GetTcpInfoFromCli() (*TcpInfo, error) {
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
	dmac := viper.GetString("dmac")

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

func GetTcpInfoFromConntrack(conn *conntrack.Conn, zone uint32, sport uint16, dport uint16) (*TcpInfo, error) {
	var zf *conntrack.FilterZone
	zf = &conntrack.FilterZone{
		Zone: uint16(zone),
	}

	cts, err := conn.DumpFilter(zf, nil)
	if err != nil {
		return nil, err
	}

	var tcpInfo *TcpInfo

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

		if ct.ProtoInfo.TCP.SeqTrack != nil {
			tuple := &ct.TupleOrig
			seqTrk := ct.ProtoInfo.TCP.SeqTrack

			tcpInfo = &TcpInfo{
				Id:      ct.ID,
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

func runCmdCtShow(cmd *cobra.Command, args []string) {
	log.Debugf("Show Conntracks")

	//OpenFlowListenAddr: viper.GetString(KeyOpenFlowListenAddr),
	zone := paramZone
	log.Debugf("zone=%d", zone)

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

	//zone := viper.GetInt("zone")
	zone := paramZone
	if zone == -1 {
		zone = 0
	}
	log.Debugf("Zone=%d", zone)

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

	//zone := viper.GetInt("zone")
	zone := paramZone
	log.Debugf("Zone=%d", zone)
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

const (
	ENABLE_TCP_TRACK        = 0x01
	ENABLE_ZONE_FILTER      = 0x02
	ENABLE_EXPORT_TCP_TRACK = 0x04
	ENABLE_DUMP_PKT         = 0x08
)

func setFlag(dest *uint32, val int, mask uint32) {
	fmt.Printf("dest=0x%x, val=%d, mask=0x%x \n", *dest, val, mask)

	if val == 1 {
		*dest |= mask
	} else if val == 0 {
		*dest &= ^mask
	}
}

func runCmdCtTrackFlag(cmd *cobra.Command, args []string) {
	log.Debugf("TCP Track Flags")

	fname := "/sys/module/vgw_driver/parameters/tcptrack_flags"
	val := readVal(fname)

	enable_tcp_track := viper.GetInt("tcp-track")
	enable_zone_filter := viper.GetInt("zone-filter")
	enable_export_tcp_track := viper.GetInt("export-tcp-track")
	enable_dump_pkt := viper.GetInt("dump-pkt")

	show := enable_tcp_track == -1 &&
		enable_zone_filter == -1 &&
		enable_export_tcp_track == -1 &&
		enable_dump_pkt == -1

	if show {
		fmt.Printf("current val=0x%x \n", val)

		var s string
		if val&ENABLE_TCP_TRACK != 0 {
			s += "enable_tcp_track "
		}

		if val&ENABLE_ZONE_FILTER != 0 {
			s += "enable_zone_filter "
		}

		if val&ENABLE_EXPORT_TCP_TRACK != 0 {
			s += "enable_export_tcp_track "
		}

		if val&ENABLE_DUMP_PKT != 0 {
			s += "enable_dump_pkt "
		}

		fmt.Printf("tcp_flags: %s \n", s)
		return
	}

	val1 := val
	setFlag(&val1, enable_tcp_track, ENABLE_TCP_TRACK)
	setFlag(&val1, enable_zone_filter, ENABLE_ZONE_FILTER)
	setFlag(&val1, enable_export_tcp_track, ENABLE_EXPORT_TCP_TRACK)
	setFlag(&val1, enable_dump_pkt, ENABLE_DUMP_PKT)

	fmt.Printf("change val=0x%x -> 0x%x \n", val, val1)
	writeVal(fname, val1)

	val2 := readVal(fname)
	if val2 != val1 {
		log.Errorf("failed to write val: expected 0x%x != current 0x%x", val1, val2)
	}
}

func readVal(fname string) uint32 {
	v, err := readSysfs(fname)
	if err != nil {
		log.Errorf("failed to read fs: filename=%s, err=%v", fname, err)
		return 0
	}

	v = strings.TrimSpace(v)
	v1, err := strconv.Atoi(v)
	if err != nil {
		log.Errorf("failed to conv string: %s, err=%v", v, err)
		return 0
	}

	return uint32(v1)
}

func writeVal(fname string, val uint32) {
	s := fmt.Sprintf("%d", val)
	err := writeSysfs(fname, s)
	if err != nil {
		log.Errorf("failed to write fs: filename=%s, err=%v", fname, err)
		return
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
