//go:build ignore

//#include <linux/types.h>
#include "common.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

//#include <linux/bpf.h>
//#include <uapi/linux/netfilter.h>
#include "vmlinux-5.14.0-362.8.1.el9_3.h"

/////////////////////////////

#include "compatibility.h"

struct sw_flow_key;
struct ovs_conntrack_info;
struct ip_tunnel_info;
struct vport;

/////////////////////////////

char __license[] SEC("license") = "Dual MIT/GPL";

extern int bpf_vgw_update_tcp_ct(struct net *net, struct sk_buff *skb, u16 family, u16 zone) __ksym;
extern int bpf_vgw_update_tcp_ct1(struct sk_buff *skb, u16 zone) __ksym;

/////////////////////////////

// fexit only support not static/inline funcion
SEC("fexit/ovs_ct_execute")
int BPF_PROG(ovs_ct_execute,struct net *net, struct sk_buff *skb, struct sw_flow_key *key, const struct ovs_conntrack_info *info, int ret)
{
	// ovs_ct_execute returns an error
	if (ret) {
		return 0;
	}

	u16 family;
	struct nf_conntrack_zone zone;
	zone = BPF_CORE_READ(info, zone);
	family = BPF_CORE_READ(info, family);
	
	bpf_vgw_update_tcp_ct(net, skb, family, zone.id); 

	return 0;
}

#if 0
SEC("fentry/ovs_ct_execute")
int BPF_PROG(ovs_ct_execute, struct net *net, struct sk_buff *skb, struct sw_flow_key *key, const struct ovs_conntrack_info *info)
{
	bpf_vgw_update_tcp_ct((struct sk_buff *)skb, 0);

	return 0;
}
#endif


#if 0
SEC("fentry/ovs_vport_send")
int BPF_PROG(ovs_vport_send,struct vport *vport, struct sk_buff *skb, u8 mac_proto)
{
	// init_net
	//struct net_device *dev = NULL;

	//dev = (struct net_device *)BPF_CORE_READ(vport, dev);
	//net = dev_net((const struct net_device *)dev);

	//u16 portId = BPF_CORE_READ(vport, port_no);

	return 0;
}
#endif

#if 0
SEC("kprobe/ovs_vport_receive")
int BPF_KPROBE(ovs_vport_receive,struct vport *vport, struct sk_buff *skb, const struct ip_tunnel_info *tun_info)
{
	//bpf_vgw_update_tcp_ct(net, skb, NFPROTO_IPV4); 
	//const char* filename;

	//struct net_device	*dev;
	//dev = BPF_CORE_READ(skb->dev, dev);


	return 0;
}
#endif



