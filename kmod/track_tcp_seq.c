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
#include <linux/moduleparam.h>


#include "vgw_version.h"

////////////////////////

#define FLAGS_ZONE_FILTER 0x01

// RW: /sys/module/vgw_driver/parameters/

uint32_t enable_track_tcp_seq = 0;
uint32_t track_flags = FLAGS_ZONE_FILTER;

// ovs port range in vgateway: 100 ~ 2099(2K)
uint32_t zone_range[2] = {100, 2099}; // min,max

module_param(enable_track_tcp_seq, uint, 0644);
MODULE_PARM_DESC(enable_track_tcp_seq, "Enable tracking TCP SEQ/ACK");

module_param(track_flags, uint, 0644);
MODULE_PARM_DESC(track_flags, "Flags of tracking");

module_param_array(zone_range, uint, NULL, 0644);
MODULE_PARM_DESC(zone_range, "Zone Range to track TCP SEQ/ACK");

/////////////////////////////////////

static struct nf_conn *get_conntrack(struct sk_buff *skb, enum ip_conntrack_info *ctinfo) 
{
	struct nf_conn *ct = NULL;

	ct = nf_ct_get(skb, ctinfo);
	if (ct == NULL || *ctinfo == IP_CT_UNTRACKED) {
		return NULL;
	}

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

static inline __u32 segment_seq_plus_len(__u32 seq,
					 size_t len,
					 unsigned int dataoff,
					 const struct tcphdr *tcph)
{
	/* XXX Should I use payload length field in IP/IPv6 header ?
	 * - YK */
	return (seq + len - dataoff - tcph->doff*4
		+ (tcph->syn ? 1 : 0) + (tcph->fin ? 1 : 0));
}


void dump_ip_tuple(struct nf_conn *ct, enum ip_conntrack_info ctinfo, const struct tcphdr *th)
{
	const struct nf_conntrack_tuple *t;
	enum ip_conntrack_dir dir;

	dir = CTINFO2DIR(ctinfo);
	t = &ct->tuplehash[dir].tuple;

	printk("tuple %p: %u %pI4:%hu -> %pI4:%hu syn=%i(%u) ack=%i(%u) fin=%i rst=%i\n",
		   t, t->dst.protonum,
		   &t->src.u3.ip, ntohs(t->src.u.all),
		   &t->dst.u3.ip, ntohs(t->dst.u.all),
		   (th->syn ? 1 : 0), ntohl(th->seq),
		   (th->ack ? 1 : 0), ntohl(th->ack_seq),
		   (th->fin ? 1 : 0), (th->rst ? 1 : 0));
}

static bool check_zone(struct nf_conn *ct)
{
	uint16_t zone;

	// NLB packets only
	zone = nf_ct_zone_id(nf_ct_zone(ct), IP_CT_DIR_ORIGINAL);

	if (!(track_flags & FLAGS_ZONE_FILTER)) {
		return true;
	} else if (zone_range[0] <= zone && zone <= zone_range[1]) {
		return true;
	}

	return false;
}

static unsigned int vgw_hook_main(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = NULL;
	int dataoff, ret = NF_ACCEPT;
	u_int8_t protonum;
	const struct tcphdr *th;
	struct tcphdr _tcph;

	if (!enable_track_tcp_seq) {
		return NF_ACCEPT;
	}

	ct = get_conntrack(skb, &ctinfo);
	if (ct == NULL) {
		return NF_ACCEPT;
	}

	// NLB packets only
	if (!check_zone(ct)) {
		return NF_ACCEPT;
	}

	// TCP only
	protonum = nf_ct_protonum(ct);
	if (protonum != IPPROTO_TCP) {
		return NF_ACCEPT;
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
	ct->proto.tcp.last_seq = ntohl(th->seq);
	ct->proto.tcp.last_ack = ntohl(th->ack_seq);
	ct->proto.tcp.last_end = segment_seq_plus_len(ntohl(th->seq), skb->len, dataoff, th);

	//dump_ip_tuple(ct, ctinfo, th);

	spin_unlock_bh(&ct->lock);
	////////////////////////////


out:
	// release it
	//nf_conntrack_put(ct);

	return ret;
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

