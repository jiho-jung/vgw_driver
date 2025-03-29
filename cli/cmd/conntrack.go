// Copyright © 2017 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"net/netip"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/subchen/go-log"
	"github.com/ti-mo/conntrack"
)

// helloCmd represents the hello command
var cmdCt = &cobra.Command{
	Use:     "conntrack",
	Aliases: []string{"ct"},
	Short:   "conntrack",
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

func init() {
	cmdCt.PersistentFlags().IntP("zone", "z", -1, "zone id")
	viper.BindPFlag("zone", cmdCt.PersistentFlags().Lookup("zone"))

	//cmdCtShow.Flags().IntP("zone", "z", -1, "zone id")
	//cmdCtShow.Flags().StringP("req-id", "", "", "req-id")
	/*
		if err := viper.BindPFlags(cmdCt.Flags()); err != nil {
			log.Errorf("failed to dump p-flags: %v", err)
		}
	*/

	cmdCt.AddCommand(cmdCtShow)

	cmdCt.AddCommand(cmdCtFlush)

	cmdCt.AddCommand(cmdCtAdd)

	// ct root cmd
	RootCmd.AddCommand(cmdCt)
}

func runCmdCtShow(cmd *cobra.Command, args []string) {
	log.Debugf("Show Conntracks")

	//OpenFlowListenAddr: viper.GetString(KeyOpenFlowListenAddr),
	zone := viper.GetInt("zone")

	c, err := conntrack.Dial(nil)
	if err != nil {
		log.Fatalf("1. %s", err)
	}

	var f *conntrack.FilterZone
	if zone != -1 {
		f = &conntrack.FilterZone{
			Zone: uint16(zone),
		}
	}

	cts, err := c.DumpFilter(f, nil)
	if err != nil {
		log.Fatalf("2. %s", err)
	}

	log.Debugf("### Start dump ct")
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
		log.Fatal(err)
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
		log.Fatal(err)
	}

	// Evict all entries from the conntrack table in the current network namespace.
	err = c.FlushFilter(f)
	if err != nil {
		log.Fatal(err)
	}
}
