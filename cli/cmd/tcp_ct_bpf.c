//go:build ignore

//#include <linux/types.h>
//#include <bpf/bpf_helpers.h>
//#include <bpf/bpf_tracing.h>

typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;
typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;

#include <bpf_helpers.h>
#include <bpf_tracing.h>
//#include <linux/bpf.h>
#include "vmlinux.h"

struct sw_flow_key;
struct ovs_conntrack_info;
struct ip_tunnel_info;
struct vport;
struct datapath;
struct sw_flow_actions;

extern int bpf_vgw_update_tcp_ct(struct net *net, struct sk_buff *skb, u16 family) __ksym;


#if 0
SEC("fentry/ovs_ct_execute")
int BPF_PROG(ovs_ct_execute, struct net *net, struct sk_buff *skb, struct sw_flow_key *key, const struct ovs_conntrack_info *info)
{
	bpf_vgw_update_tcp_ct((struct sk_buff *)skb, 0);

	return 0;
}
#endif

#if 1
// fexit only support not static/inline funcion
SEC("fexit/ovs_ct_execute")
int BPF_PROG(ovs_ct_execute,struct net *net, struct sk_buff *skb, struct sw_flow_key *key, const struct ovs_conntrack_info *info, int ret)
{
	if (ret) {
		return 0;
	}
	
	bpf_vgw_update_tcp_ct(net, skb, NFPROTO_IPV4); 

	return 0;
}
#endif

char __license[] SEC("license") = "Dual MIT/GPL";

