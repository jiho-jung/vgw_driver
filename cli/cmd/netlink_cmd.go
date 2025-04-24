package cmd

// https://github.com/a-zaki/genl_ex/blob/master/genl_ex.c
// https://github.com/mdlayher/wifi/tree/main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/subchen/go-log"
	"github.com/ti-mo/conntrack"
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

	cmdGeneralShow.Flags().Uint16P("sport", "", 0, "src port")
	cmdGeneralShow.Flags().Uint16P("dport", "", 0, "dst port")
	cmdNetlink.AddCommand(cmdGeneralShow)

	// ct root cmd
	RootCmd.AddCommand(cmdNetlink)
}

func runGenShow(cmd *cobra.Command, args []string) {
	log.Debugf("Show Conntracks by netlink")

	vgwconn, err := ConnectVgatewayNetlink()
	if err != nil {
		log.Errorf("failed to connect Vgateway netlink: err=%v", err)
		return
	}
	defer vgwconn.Close()

	sport := viper.GetUint16("sport")
	dport := viper.GetUint16("dport")

	c, err := conntrack.Dial(nil)
	if err != nil {
		log.Errorf("failed to connect netlink: err=%v", err)
		return
	}
	defer c.Close()

	zone := uint32(100)
	tcpInfo, err := GetTcpInfoFromConntrack(c, zone, sport, dport)
	if err != nil {
		log.Errorf("failed to get tcp infos: %v", err)
		return
	} else if tcpInfo == nil {
		log.Error("no tcp session")
		return
	}

	fmt.Printf("TCPInfo: %+v \n", tcpInfo)

	tcpseq, err := GetTcpSeq(vgwconn, zone, tcpInfo)
	if err != nil {
		log.Errorf("failed to get tcp seq: %v", err)
		return
	}

	fmt.Printf("TCPSEQ: %+v \n", tcpseq)
}
