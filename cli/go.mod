module github.com/vgw_driver

go 1.24.2

require (
	github.com/Djarvur/go-lsmod v0.0.0-20190124055245-f58e2c8a3519
	github.com/cilium/ebpf v0.18.0
	github.com/google/gopacket v1.1.19
	github.com/spf13/cobra v1.9.1
	github.com/spf13/viper v1.20.1
	github.com/subchen/go-log v3.0.0+incompatible
	github.com/ti-mo/conntrack v0.5.1
	golang.org/x/net v0.36.0
	pault.ag/go/modprobe v0.2.0
)

require (
	github.com/fsnotify/fsnotify v1.8.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.2.1 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	github.com/pelletier/go-toml/v2 v2.2.3 // indirect
	github.com/pierrec/lz4 v2.6.1+incompatible // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sagikazarmark/locafero v0.7.0 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.12.0 // indirect
	github.com/spf13/cast v1.7.1 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/ti-mo/netfilter v0.5.2 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.9.0 // indirect
	golang.org/x/sync v0.11.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/text v0.22.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	pault.ag/go/topsort v0.1.1 // indirect
)

replace github.com/ti-mo/conntrack => github.com/joyent/conntrack v0.5.3-0.20250407014621-4b383a5baecc
