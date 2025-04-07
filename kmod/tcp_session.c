#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/rculist.h>
#include <linux/rculist_nulls.h>
#include <linux/types.h>
#include <linux/timer.h>
#include <linux/security.h>
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <linux/netlink.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/siphash.h>

#include <linux/netfilter.h>
#include <net/netlink.h>
#include <net/sock.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_seqadj.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_timestamp.h>
#include <net/netfilter/nf_conntrack_labels.h>
#include <net/netfilter/nf_conntrack_synproxy.h>
#if IS_ENABLED(CONFIG_NF_NAT)
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_helper.h>
#endif

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>

#include "nf_internals.h"

// use shared memory
// zone range : 100 ~ 2999(2k)
// new   session count: 4 Bytes
//  - tcp: 8K
//  - udp: 8K
// total session count: 4 Bytes
//  - tcp: 8K
//  - udpL 8K

// set syn_recv because vgateway work on asymmetric, so it never see syn_ack 
int vgw_update_tcp_state(struct nf_conn *ct)
{
	// 1) set SYN_RECVED
	// 2) tcp_be_liberal

	struct ip_ct_tcp *tcp_info;
	u_int8_t l4proto = nf_ct_protonum(ct);

	if (l4proto != IPPROTO_TCP) {
		return 0;
	}

	spin_lock_bh(&ct->lock);

	tcp_info = &ct->proto.tcp;

	if (tcp_info->state == TCP_CONNTRACK_SYN_SENT) {
		tcp_info->state = TCP_CONNTRACK_SYN_RECV;

		// be liberal from tcp window
		tcp_info->seen[0].flags |= IP_CT_TCP_FLAG_BE_LIBERAL;
		tcp_info->seen[1].flags |= IP_CT_TCP_FLAG_BE_LIBERAL;
	}

	spin_unlock_bh(&ct->lock);

	return 0;
}

struct ip_ct_tcp_state_vgw {
	u_int32_t	td_end;		/* max of seq + len */
	u_int32_t	td_maxend;	/* max of ack + max(win, 1) */
	u_int32_t	td_maxwin;	/* max(win) */
	u_int32_t	td_maxack;	/* max of ack */
	u_int8_t	td_scale;	/* window scale factor */
	u_int8_t	flags;		/* per direction options */
	u_int16_t	dummy;
}; // 20 bytes

struct ip_ct_tcp_vgw {
	// 40 bytes
	struct ip_ct_tcp_state_vgw seen[2];	/* connection parameters per direction */
	//  24 bytes
	u_int8_t	state;		/* state of the connection (enum tcp_conntrack) */
	/* For detecting stale connections */
	u_int8_t	last_dir;	/* Direction of the last packet (enum ip_conntrack_dir) */
	u_int8_t	retrans;	/* Number of retransmitted packets */
	u_int8_t	last_index;	/* Index of the last packet */
	u_int32_t	last_seq;	/* Last sequence number seen in dir */
	u_int32_t	last_ack;	/* Last sequence number seen in opposite dir */
	u_int32_t	last_end;	/* Last seq + len */
	u_int16_t	last_win;	/* Last window advertisement seen in dir */
	/* For SYN packets while we may be out-of-sync */
	u_int8_t	last_wscale;	/* Last window scaling factor seen */
	u_int8_t	last_flags;	/* Last flags set */
	u_int32_t   dummy;
}; // 64 bytes

#if 0
struct ip_ct_tcp_seq_track {
	// forward dir of seen
	u_int32_t	td_end;		/* max of seq + len */
	u_int32_t	td_maxend;	/* max of ack + max(win, 1) */
	u_int32_t	td_maxwin;	/* max(win) */
	u_int32_t	td_maxack;	/* max of ack */

	// 
	u_int32_t	last_seq;	/* Last sequence number seen in dir */
	u_int32_t	last_ack;	/* Last sequence number seen in opposite dir */
	u_int32_t	last_end;	/* Last seq + len */
	u_int16_t	last_win;	/* Last window advertisement seen in dir */
	u_int8_t	last_wscale;/* Last window scaling factor seen */
	u_int8_t    dummy;
};
#endif

#define CTA_PROTOINFO_TCP_SEQ_TRACK __CTA_PROTOINFO_TCP_MAX

static int tcp_to_nlattr(struct sk_buff *skb, struct nlattr *nla, struct nf_conn *ct, bool destroy)
{
	struct nlattr *nest_parms;
	struct nf_ct_tcp_flags tmp = {};
	//struct ip_ct_tcp_seq_track seq_trk = {};
	struct ip_ct_tcp_vgw seq_trk = {};

	spin_lock_bh(&ct->lock);
	nest_parms = nla_nest_start(skb, CTA_PROTOINFO_TCP);
	if (!nest_parms)
		goto nla_put_failure;

	if (nla_put_u8(skb, CTA_PROTOINFO_TCP_STATE, ct->proto.tcp.state))
		goto nla_put_failure;

	if (destroy)
		goto skip_state;

	if (nla_put_u8(skb, CTA_PROTOINFO_TCP_WSCALE_ORIGINAL,
		       ct->proto.tcp.seen[0].td_scale) ||
	    nla_put_u8(skb, CTA_PROTOINFO_TCP_WSCALE_REPLY,
		       ct->proto.tcp.seen[1].td_scale))
		goto nla_put_failure;

	tmp.flags = ct->proto.tcp.seen[0].flags;
	if (nla_put(skb, CTA_PROTOINFO_TCP_FLAGS_ORIGINAL,
		    sizeof(struct nf_ct_tcp_flags), &tmp))
		goto nla_put_failure;

	tmp.flags = ct->proto.tcp.seen[1].flags;
	if (nla_put(skb, CTA_PROTOINFO_TCP_FLAGS_REPLY,
		    sizeof(struct nf_ct_tcp_flags), &tmp))
		goto nla_put_failure;

#if 0
	seq_trk.td_end = ct->proto.tcp.seen[0].td_end;
	seq_trk.td_maxend = ct->proto.tcp.seen[0].td_maxend;
	seq_trk.td_maxwin = ct->proto.tcp.seen[0].td_maxwin;
	seq_trk.td_maxack = ct->proto.tcp.seen[0].td_maxack;

	seq_trk.last_seq = ct->proto.tcp.last_seq;
	seq_trk.last_ack = ct->proto.tcp.last_ack;
	seq_trk.last_end = ct->proto.tcp.last_end;
	seq_trk.last_win = ct->proto.tcp.last_win;
	seq_trk.last_wscale = ct->proto.tcp.last_wscale;
#endif

	for (int i=0; i<2; i++) {
		seq_trk.seen[i].td_end = ct->proto.tcp.seen[i].td_end;
		seq_trk.seen[i].td_maxend = ct->proto.tcp.seen[i].td_maxend;
		seq_trk.seen[i].td_maxwin = ct->proto.tcp.seen[i].td_maxwin;
		seq_trk.seen[i].td_maxack = ct->proto.tcp.seen[i].td_maxack;
		seq_trk.seen[i].td_scale = ct->proto.tcp.seen[i].td_scale;
		seq_trk.seen[i].flags = ct->proto.tcp.seen[i].flags;
	}

	seq_trk.state = ct->proto.tcp.state;
	seq_trk.last_dir = ct->proto.tcp.last_dir;
	seq_trk.retrans = ct->proto.tcp.retrans;
	seq_trk.last_index = ct->proto.tcp.last_index;
	seq_trk.last_seq = ct->proto.tcp.last_seq;
	seq_trk.last_ack = ct->proto.tcp.last_ack;
	seq_trk.last_end = ct->proto.tcp.last_end;
	seq_trk.last_win = ct->proto.tcp.last_win;
	seq_trk.last_wscale = ct->proto.tcp.last_wscale;
	seq_trk.last_flags = ct->proto.tcp.last_flags;

	if (nla_put(skb, CTA_PROTOINFO_TCP_SEQ_TRACK,
		    //sizeof(struct ip_ct_tcp_seq_track), &seq_trk))
		    sizeof(struct ip_ct_tcp_vgw), &seq_trk))
		goto nla_put_failure;

skip_state:
	spin_unlock_bh(&ct->lock);
	nla_nest_end(skb, nest_parms);

	return 0;

nla_put_failure:
	spin_unlock_bh(&ct->lock);
	return -1;
}

int vgw_dump_tcp_protoinfo(struct sk_buff *skb, struct nf_conn *ct, bool destroy)
{
	// 3) add protoinfo_tcp_seq

	struct nlattr *nest_proto;
	int ret;

	u_int8_t proto = nf_ct_protonum(ct);
	if (proto != IPPROTO_TCP)
		return -1;

	nest_proto = nla_nest_start(skb, CTA_PROTOINFO);
	if (!nest_proto)
		goto nla_put_failure;

	ret = tcp_to_nlattr(skb, nest_proto, ct, destroy);

	nla_nest_end(skb, nest_proto);

	return ret;

nla_put_failure:
	return -1;
}

