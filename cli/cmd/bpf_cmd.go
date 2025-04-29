package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/subchen/go-log"
	"github.com/vgw_driver/pkg/bpf"
)

var cmdBpf = &cobra.Command{
	Use:     "bpf",
	Aliases: []string{"bpf"},
	Short:   "bpf",
}

var cmdBpfRun = &cobra.Command{
	Use:     "run",
	Aliases: []string{"r"},
	Short:   "run bpf",
	Run:     runCmdBpfRun,
}

func init() {
	//cmdBpf.PersistentFlags().IntP("zone", "z", -1, "zone id, -1: use cli parameter, >=0: use ct")
	//viper.BindPFlag("zone", cmdBpf.PersistentFlags().Lookup("zone"))

	cmdBpfRun.Flags().Uint32P("wait", "w", 10, "wait seconds")

	if err := viper.BindPFlags(cmdBpfRun.Flags()); err != nil {
		log.Errorf("failed to dump p-flags: %v", err)
	}

	cmdBpf.AddCommand(cmdBpfRun)

	// bpf root cmd
	RootCmd.AddCommand(cmdBpf)
}

func runCmdBpfRun(cmd *cobra.Command, args []string) {
	log.Debugf("Run bpf")

	w := viper.GetUint32("wait")

	vgwBpf, err := bpf.NewBpfLoader()
	if err != nil {
		fmt.Printf("failed to create bpf: err=%v \n", err)
		return
	} else if err = vgwBpf.Load(ctx); err != nil {
		fmt.Printf("failed to load bpf: err=%v \n", err)
		return
	}
	defer vgwBpf.Close()

	log.Debugf("Waiting %d sec", w)
	time.Sleep(time.Second * time.Duration(w))
}
