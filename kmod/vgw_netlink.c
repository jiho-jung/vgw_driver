#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/export.h>
#include <net/genetlink.h>

#include <linux/netfilter.h>
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

#include "vgw_netlink.h"
#include "vgw_version.h"

// https://www.electronicsfaq.com/2014/02/generic-netlink-sockets-example-code.html

static struct genl_family vgw_genl_family;

struct tcp_seq_filter {
	uint32_t id;
	uint32_t zone;
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t protocol;
	uint8_t dummy[3];
};

struct tcp_seq {
	uint32_t id; // id in conntrack and tcp_seq_filter
	uint32_t seq;
	uint32_t ack;
};

static int looup_conntrack_by_filter(struct sk_buff *skb, struct genl_info *info, struct tcp_seq_filter *flt) 
{
	struct nf_conntrack_zone zone = {};
	struct nf_conntrack_tuple_hash *h;
	struct nf_conntrack_tuple tuple = {};
	struct tcp_seq res_seq = {};
	struct nf_conn *ct;
	struct net *net;
	__be32 id = 0;

	zone.id = (uint16_t)flt->zone;
	zone.dir = NF_CT_ZONE_DIR_ORIG;
	net = genl_info_net(info);

	tuple.src.l3num = NFPROTO_IPV4;
	tuple.src.u3.ip = htonl(flt->src_ip);
	tuple.dst.u3.ip = htonl(flt->dst_ip);
	tuple.src.u.udp.port = htons(flt->src_port);
	tuple.dst.u.udp.port = htons(flt->dst_port);
	tuple.dst.protonum = flt->protocol;
	tuple.dst.dir = IP_CT_DIR_ORIGINAL;

	h = nf_conntrack_find_get(net, &zone, &tuple);
	if (!h) {
		return 0;
	}

	ct = nf_ct_tuplehash_to_ctrack(h);
	if (ct == NULL) {
		return 0;
	}

	id = ntohl(nf_ct_get_id(ct));
	if (flt->id != id) {
		goto out;
	}

	res_seq.id = id;
	res_seq.seq = ct->proto.tcp.last_seq;
	res_seq.ack = ct->proto.tcp.last_ack;

	if (nla_put(skb, VGW_NL_CT_ATTR_TCP_SEQ, sizeof(struct tcp_seq), &res_seq)) {
		pr_err("failed to put tcpseq into response skb\n");
		goto out;
	}

out:
	if (ct != NULL) {
		nf_ct_put(ct);
	}

	return 0;
}

int dump_conntrack_tcp_seq(struct sk_buff *skb2, struct genl_info *info, struct tcp_seq_filter* flt) 
{
	struct sk_buff *skb;
	int ret = 0;
	void *msg_head;

	if (info == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	//Send a message back
	//Allocate some memory, since the size is not yet known use NLMSG_GOODSIZE
	skb = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (skb == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	//Create the message headers
	msg_head = genlmsg_put(skb, 0, info->snd_seq, &vgw_genl_family, 0, VGW_NL_CT_CMD_DUMP);
	if (msg_head == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	looup_conntrack_by_filter(skb, info, flt);

	//Finalize the message
	genlmsg_end(skb, msg_head);

	//Send the message back
	ret = genlmsg_unicast(genl_info_net(info), skb, info->snd_portid);
	if (ret != 0) {
		goto out;
	}

	return 0;

out:
	pr_info("An error occured in dump_conntrack_tcp_seq: ret=%d\n", ret);
	return ret;
}

static int vgw_genl_rx_msg(struct sk_buff* skb, struct genl_info* info)
{
	struct tcp_seq_filter *flt;
	int ret;

	if (!info->attrs[VGW_NL_CT_ATTR_FILTER]) {
		pr_err("Empty filter: port= %u\n", info->snd_portid);
		return -EINVAL;
	}

	flt = (struct tcp_seq_filter*)nla_data(info->attrs[VGW_NL_CT_ATTR_FILTER]);
	//pr_debug("port=%u, ct_id=%u, zone=%u, snd_seq=%u \n", info->snd_portid, flt->id, flt->zone, info->snd_seq);

	ret = dump_conntrack_tcp_seq(skb, info, flt);
	if (ret != 0) {
		pr_info("failed to dump conntrack tcp seq: err=%d\n", ret);
	}

	return ret;
}

static struct nla_policy vgw_genl_policy[VGW_NL_CT_ATTR_MAX+1] = {
	[VGW_NL_CT_ATTR_FILTER] = {
		.type = NLA_BINARY,
		.len = 24
	},
};

static const struct genl_ops vgw_genl_ops[] = {
	{
		.cmd = VGW_NL_CT_CMD_DUMP,
		.policy = vgw_genl_policy,
		.doit = vgw_genl_rx_msg,
		.dumpit = NULL,
	},
};

static struct genl_family vgw_genl_family = {
	.name = VGW_NL_CT_FAMILY_NAME,
	.version = 1,
	.maxattr = VGW_NL_CT_ATTR_MAX,
	.netnsok = false,
	.module = THIS_MODULE,
	.ops = vgw_genl_ops,
	.n_ops = ARRAY_SIZE(vgw_genl_ops),
};

int vgw_genl_init(void)
{
	int ret;

	pr_info("Init VGW General Netlink Module: %s\n", VERSION_STRING);

	ret = genl_register_family(&vgw_genl_family);
	if (ret)
		goto failure;

	return 0;

failure:
	pr_err("VGW General Netlink: error occurred in %s\n", __func__);
	return -EINVAL;
}

void vgw_genl_exit(void)
{
	pr_info("Exit VGW General Netlink Module: %s\n", VERSION_STRING);
	genl_unregister_family(&vgw_genl_family);
}

