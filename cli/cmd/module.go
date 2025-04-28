package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/subchen/go-log"
	lsmod "github.com/yxxhero/go-lsmod"
	"pault.ag/go/modprobe"
)

var cmdMod = &cobra.Command{
	Use:     "module",
	Aliases: []string{"mod"},
	Short:   "Kernel Module",
	Long:    `Kernel Module `,
}

var cmdModLoad = &cobra.Command{
	Use:     "load",
	Aliases: []string{"ld"},
	Short:   "load module",
	Run:     runModLoad,
}

var cmdModRemove = &cobra.Command{
	Use:     "remove",
	Aliases: []string{"rm"},
	Short:   "remove module",
	Run:     runModRemove,
}

var cmdModProbe = &cobra.Command{
	Use:     "probe",
	Aliases: []string{"pr"},
	Short:   "probe module",
	Run:     runModProbe,
}

var cmdModList = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "list module",
	Run:     runModList,
}

func init() {
	cmdMod.PersistentFlags().StringP("name", "n", "", "Kernel Module name")
	cmdMod.PersistentFlags().StringP("path", "p", "", "Kernel Module path")
	viper.BindPFlag("name", cmdMod.PersistentFlags().Lookup("name"))
	viper.BindPFlag("path", cmdMod.PersistentFlags().Lookup("path"))

	cmdMod.AddCommand(cmdModLoad)
	cmdMod.AddCommand(cmdModRemove)
	cmdMod.AddCommand(cmdModProbe)
	cmdMod.AddCommand(cmdModList)

	RootCmd.AddCommand(cmdMod)
}

func int8ToStr(arr []int8) string {
	b := make([]byte, 0, len(arr))
	for _, v := range arr {
		if v == 0x00 {
			break
		}
		b = append(b, byte(v))
	}
	return string(b)
}

func GetOsRelease() string {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err == nil {
		// extract members:
		// type Utsname struct {
		//  Sysname    [65]int8
		//  Nodename   [65]int8
		//  Release    [65]int8
		//  Version    [65]int8
		//  Machine    [65]int8
		//  Domainname [65]int8
		// }

		/*
			fmt.Printf("### name: %s \n", int8ToStr(uname.Sysname[:]))
			fmt.Printf("### release: %s \n", int8ToStr(uname.Release[:]))
			fmt.Printf("### version: %s \n", int8ToStr(uname.Version[:]))
		*/

		rel := int8ToStr(uname.Release[:])

		return rel
	}

	return ""
}

func runModLoad(cmd *cobra.Command, args []string) {
	log.Debugf("Load Module")

	kpath := viper.GetString("path")
	if len(kpath) < 1 {
		kpath = "/opt/kraken/kmod"
	}

	kname := viper.GetString("name")
	if len(kname) < 1 {
		kname = "vgw_driver"

		rel := GetOsRelease()
		if len(rel) > 1 {
			// vgw_driver_5.14.0-362.8.1.el9_3.x86_64.ko
			kname += "_" + rel
		}

		kname += ".ko"
	}

	if len(kname) < 1 {
		log.Errorf("Module name is empyt")
		return
	}

	log.Infof("Load kernel module: %s/%s", kpath, kname)
	err := loadDriver(kpath, kname)
	if err != nil {
		log.Errorf("%v", err)
	}
}

func runModRemove(cmd *cobra.Command, args []string) {
	log.Debugf("Remove Module")

	kname := viper.GetString("name")

	if len(kname) < 1 {
		log.Errorf("Module name is empyt")
		return
	}

	err := removeDriver(kname)
	if err != nil {
		log.Errorf("%v", err)
	}
}

func runModProbe(cmd *cobra.Command, args []string) {
	log.Debugf("Probe Module")

	kname := viper.GetString("name")

	if len(kname) < 1 {
		log.Errorf("Module name is empyt")
		return
	}

	err := probeDriver(kname)
	if err != nil {
		log.Errorf("%v", err)
	}
}

func runModList(cmd *cobra.Command, args []string) {
	log.Debugf("List Module")

	kname := viper.GetString("name")
	if len(kname) < 1 {
		log.Errorf("Module name is empyt")
		return
	}

	err := listDriver(kname)
	if err != nil {
		log.Errorf("%v", err)
	}
}

func loadDriver(kpath string, kname string) error {
	modPath := filepath.Join(kpath, kname)

	f, err := os.Open(modPath)
	if err != nil {
		return fmt.Errorf("failed to open module file: name=%s, err=%s", modPath, err)
	}
	defer f.Close()

	err = modprobe.Init(f, "")
	if err != nil {
		return fmt.Errorf("failed to init module file: name=%s, err=%s", modPath, err)
	}

	return nil
}

func removeDriver(kname string) error {
	err := modprobe.Remove(kname)
	if err != nil {
		return fmt.Errorf("failed to remove module file: name=%s, err=%s", kname, err)
	}

	return nil
}

func probeDriver(kname string) error {
	err := modprobe.Load(kname, "")
	if err != nil {
		return fmt.Errorf("failed to probe module file: name=%s, err=%s", kname, err)
	}

	return nil
}

func listDriver(kname string) error {
	if len(kname) < 1 {
		return fmt.Errorf("Module name is empyt")
	}

	mods, err := lsmod.LsMod("")
	if err != nil {
		return fmt.Errorf("failed to list module info: err=%s", err)
	}

	//_, _ = lsmod.IsLoaded()

	mod, ok := mods[kname]
	if !ok {
		return fmt.Errorf("No such module")
	}

	fmt.Printf("%s: %+v \n", kname, mod)

	return nil
}
