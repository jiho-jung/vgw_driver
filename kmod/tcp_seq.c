#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_nat_helper.h>
#include <net/netfilter/nf_conntrack_seqadj.h>
#include <net/tcp.h>

#include "vgw_version.h"

////////////////////////

#define FLAGS_ENABLE_ZONE_FILTER 0x01

// RW: /sys/modules/vgw_driver/parameters/running_flags

uint32_t enable_service = 0;
uint32_t running_flags = FLAGS_ENABLE_ZONE_FILTER;

module_param(enable_service, uint, 0644);
module_param(running_flags, uint, 0644);

/////////////////////////////////////

static struct nf_conn *get_conntrack(struct sk_buff *skb, enum ip_conntrack_info *ctinfo) 
{
	struct nf_conn *ct = NULL;

	ct = nf_ct_get(skb, ctinfo);
	if (ct == NULL || *ctinfo == IP_CT_UNTRACKED) {
		return NULL;
	}

	/*
	if (nf_ct_is_untracked(ct)) {
	return NULL;
	}
	*/

	return ct;
}

static int ipv4_get_l4proto(const struct sk_buff *skb, unsigned int nhoff,
			    u_int8_t *protonum)
{
	int dataoff = -1;
	const struct iphdr *iph;
	struct iphdr _iph;

	iph = skb_header_pointer(skb, nhoff, sizeof(_iph), &_iph);
	if (!iph)
		return -1;

	/* Conntrack defragments packets, we might still see fragments
	 * inside ICMP packets though.
	 */
	if (iph->frag_off & htons(IP_OFFSET))
		return -1;

	dataoff = nhoff + (iph->ihl << 2);
	*protonum = iph->protocol;

	/* Check bogus IP headers */
	if (dataoff > skb->len) {
		pr_debug("bogus IPv4 packet: nhoff %u, ihl %u, skblen %u\n",
			 nhoff, iph->ihl << 2, skb->len);
		return -1;
	}
	return dataoff;
}

static int get_l4proto(const struct sk_buff *skb, unsigned int nhoff, u8 pf, u8 *l4num) 
{
	switch (pf) {
	case NFPROTO_IPV4:
		return ipv4_get_l4proto(skb, nhoff, l4num);

	default:
		*l4num = 0;
		break;
	}
	return -1;
}

/* Protect conntrack agaist broken packets. Code taken from ipt_unclean.c.  */
static bool tcp_error(const struct tcphdr *th,
		      struct sk_buff *skb,
		      unsigned int dataoff,
		      const struct nf_hook_state *state)
{
	unsigned int tcplen = skb->len - dataoff;

	/* Not whole TCP header or malformed packet */
	if (th->doff*4 < sizeof(struct tcphdr) || tcplen < th->doff*4) {
		//tcp_error_log(skb, state, "truncated packet");
		return true;
	}

	return false;
}

void dump_ip_tuple(const struct nf_conntrack_tuple *t, const struct tcphdr *th)
{
	printk("tuple %p: %u %pI4:%hu -> %pI4:%hu syn=%i(%u) ack=%i(%u) fin=%i rst=%i\n",
			 t, t->dst.protonum,
			 &t->src.u3.ip, ntohs(t->src.u.all),
			 &t->dst.u3.ip, ntohs(t->dst.u.all),
			 (th->syn ? 1 : 0), ntohl(th->seq),
			 (th->ack ? 1 : 0), ntohl(th->ack_seq),
			 (th->fin ? 1 : 0), (th->rst ? 1 : 0));
}

static unsigned int vgw_hook_main(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = NULL;
	int dataoff, ret = NF_ACCEPT;
	u_int8_t protonum;
	const struct tcphdr *th;
	struct tcphdr _tcph;
	uint16_t zone;
	struct nf_conntrack_tuple *tuple;
	enum ip_conntrack_dir dir;

	if (!enable_service) {
		return NF_ACCEPT;
	}

	ct = get_conntrack(skb, &ctinfo);
	if (ct == NULL) {
		return ret;
	}

	// NLB packets only
	zone = nf_ct_zone_id(nf_ct_zone(ct), IP_CT_DIR_ORIGINAL);
	if ((running_flags & FLAGS_ENABLE_ZONE_FILTER) && 
		zone == NF_CT_DEFAULT_ZONE_ID) {
		goto out;
	}

	// TCP only
	protonum = nf_ct_protonum(ct);
	if (protonum != IPPROTO_TCP) {
		goto out;
	}

	// hold the ct
	//nf_conntrack_get(&ct->ct_general);

	dataoff = get_l4proto(skb, skb_network_offset(skb), state->pf, &protonum);
	if (dataoff <= 0) {
		pr_debug("not prepared to track yet or error occurred\n");
		goto out;
	}

	th = skb_header_pointer(skb, dataoff, sizeof(_tcph), &_tcph);
	if (th == NULL)
		goto out;

	if (tcp_error(th, skb, dataoff, state))
		goto out;

	/////////////////////
	spin_lock_bh(&ct->lock);

	// XXX: set seq/ack
	//tmp.flags = ct->proto.tcp.seen[0].flags;

	dir = CTINFO2DIR(ctinfo);
	tuple = &ct->tuplehash[dir].tuple;
	dump_ip_tuple(tuple, th);

	spin_unlock_bh(&ct->lock);
	/////////////////////

out:
	// release it
	//nf_conntrack_put(ct);

	return NF_ACCEPT;
}

struct nf_hook_ops input_hook_ops = {
	.hooknum = NF_INET_LOCAL_IN,
	.hook = vgw_hook_main,
	.pf = PF_INET,

	//.priority = NF_IP_PRI_FILTER + 1};
	.priority = NF_IP_PRI_CONNTRACK_HELPER + 1
};


int vgw_conntrack_init(void) 
{
	pr_info("Init VGW Conntrack Module: %s\n", VERSION_STRING);

	nf_register_net_hook(&init_net,&input_hook_ops);

	return 0;
}

void vgw_conntrack_exit(void)
{
	pr_info("Exit VGW Conntrack Module: %s\n", VERSION_STRING);

	nf_unregister_net_hook(&init_net, &input_hook_ops);
}

