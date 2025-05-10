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
#include <net/netfilter/nf_tables.h>
#include <net/netfilter/nf_conntrack_timeout.h>
#include <net/tcp.h>
#include <linux/moduleparam.h>

#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/filter.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/btf_ids.h>
#include <linux/net_namespace.h>
#include <net/netfilter/nf_conntrack_bpf.h>
#include <net/netfilter/nf_conntrack_core.h>

#include "vgw_version.h"
#include "tcp_session.h"
#include "flow.h"
#include "compatibility.h"

////////////////////////

// RW: /sys/module/vgw_driver/parameters/

uint32_t tcptrack_flags = FLAGS_ZONE_FILTER;

// ovs port range in vgateway: 100 ~ 2099(2K)
uint32_t zone_range[2] = {100, 2099}; // min,max

module_param(tcptrack_flags, uint, 0644);
MODULE_PARM_DESC(tcptrack_flags, "Flags of tcptrack");

module_param_array(zone_range, uint, NULL, 0644);
MODULE_PARM_DESC(zone_range, "Zone Range to track TCP SEQ/ACK");

int kprobe_init(void);
void  kprobe_exit(void);

/////////////////////////////////////

static struct nf_conn* 
get_skb_ct(struct sk_buff *skb, enum ip_conntrack_info *ctinfo) 
{
	struct nf_conn *ct = NULL;

	ct = nf_ct_get(skb, ctinfo);
	if (ct == NULL || *ctinfo == IP_CT_UNTRACKED) {
		return NULL;
	}

	return ct;
}

#if 0
/* This replicates logic from nf_conntrack_core.c that is not exported. */
static enum ip_conntrack_info
ct_get_info(const struct nf_conntrack_tuple_hash *h)
{
	const struct nf_conn *ct = nf_ct_tuplehash_to_ctrack(h);

	if (NF_CT_DIRECTION(h) == IP_CT_DIR_REPLY)
		return IP_CT_ESTABLISHED_REPLY;
	/* Once we've had two way comms, always ESTABLISHED. */
	if (test_bit(IPS_SEEN_REPLY_BIT, &ct->status))
		return IP_CT_ESTABLISHED;
	if (test_bit(IPS_EXPECTED_BIT, &ct->status))
		return IP_CT_RELATED;
	return IP_CT_NEW;
}
#endif

static struct nf_conn* 
lookup_conntrack_by_skb(struct net *net, const struct nf_conntrack_zone *zone, u8 l3num, struct sk_buff *skb, bool natted)
{
	struct nf_conntrack_tuple tuple;
	struct nf_conntrack_tuple_hash *h;
	struct nf_conn *ct;

	if (!nf_ct_get_tuplepr(skb, skb_network_offset(skb), l3num, net, &tuple)) {
		pr_err("lookup_conntrack_by_skb: Can't get tuple\n");
		return NULL;
	}

	/* look for tuple match */
	h = nf_conntrack_find_get(net, zone, &tuple);
	if (!h)
		return NULL;   /* Not found. */

	ct = nf_ct_tuplehash_to_ctrack(h);

	// XXX: consider
	//nf_ct_set(skb, ct, ct_get_info(h));

	return ct;
}

static int
ipv4_get_l4proto(const struct sk_buff *skb, unsigned int nhoff, u_int8_t *protonum)
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

/* Protect conntrack agaist broken packets. Code taken from ipt_unclean.c.  */
static bool
tcp_error(const struct tcphdr *th, struct sk_buff *skb, unsigned int dataoff) 
{
	unsigned int tcplen = skb->len - dataoff;

	/* Not whole TCP header or malformed packet */
	if (th->doff*4 < sizeof(struct tcphdr) || tcplen < th->doff*4) {
		//tcp_error_log(skb, state, "truncated packet");
		return true;
	}

	return false;
}

static __u32
segment_seq_plus_len(__u32 seq, size_t len, unsigned int dataoff, const struct tcphdr *tcph)
{
	/* XXX Should I use payload length field in IP/IPv6 header ?
	 * - YK */
	return (seq + len - dataoff - tcph->doff*4
		+ (tcph->syn ? 1 : 0) + (tcph->fin ? 1 : 0));
}

__always_inline static void
dump_ip_tuple(struct nf_conn *ct, enum ip_conntrack_info ctinfo, const struct tcphdr *th)
{
	const struct nf_conntrack_tuple *t;
	enum ip_conntrack_dir dir;

	dir = CTINFO2DIR(ctinfo);
	t = &ct->tuplehash[dir].tuple;

	printk("tcptrack tuple: %u %pI4:%hu->%pI4:%hu syn=%i(%u) ack=%i(%u) fin=%i rst=%i\n",
		   t->dst.protonum,
		   &t->src.u3.ip, ntohs(t->src.u.all),
		   &t->dst.u3.ip, ntohs(t->dst.u.all),
		   (th->syn ? 1 : 0), ntohl(th->seq),
		   (th->ack ? 1 : 0), ntohl(th->ack_seq),
		   (th->fin ? 1 : 0), (th->rst ? 1 : 0));
}

void
dump_skb_ct(const struct sk_buff *skb, struct nf_conn *ct, uint32_t ctinfo, u16 zone, struct sw_flow_key *key)
{
	u_int8_t protonum;
	const struct iphdr *iph;
	struct iphdr _iph;
	int nhoff = skb_network_offset(skb);
	const struct tcphdr *th;
	struct tcphdr _tcph;
	int dataoff;

	iph = skb_header_pointer(skb, nhoff, sizeof(_iph), &_iph);
	if (!iph) {
		printk("tcptrack: no ip hdr \n");
		return;
	}

	dataoff = ipv4_get_l4proto(skb, nhoff, &protonum);
	if (dataoff <= 0) {
		printk("tcptrack: not prepared to track yet or error occurred\n");
		return;
	}

	th = skb_header_pointer(skb, dataoff, sizeof(_tcph), &_tcph);
	if (th == NULL) {
		printk("tcptack: no tcp hdr \n");
		return;
	}

	printk("TCP Track skb=0x%p id:%u proto:%u %pI4:%hu->%pI4:%hu S=%i:%u A=%i:%u %c%c status=0x%x:0x%lx:0x%x zone=%d, recirc_id=%d\n",
		   skb,
		   ntohs(iph->id),
		   protonum,
		   &iph->saddr, ntohs(th->source),
		   &iph->daddr, ntohs(th->dest),
		   (th->syn ? 1 : 0), ntohl(th->seq),
		   (th->ack ? 1 : 0), ntohl(th->ack_seq),
		   (th->fin ? 'F' : ' '), (th->rst ? 'R' : ' '),
		   ctinfo,
		   ct->status,
		   key->ct_state,
		   zone, key->recirc_id);
}

void dump_skb(char *msg, const struct sk_buff *skb) 
{
	u_int8_t protonum;
	const struct iphdr *iph;
	struct iphdr _iph;
	int nhoff = skb_network_offset(skb);
	const struct tcphdr *th;
	struct tcphdr _tcph;
	int dataoff;

	iph = skb_header_pointer(skb, nhoff, sizeof(_iph), &_iph);
	if (!iph) {
		printk("tcptrack: no ip hdr \n");
		return;
	}

	dataoff = ipv4_get_l4proto(skb, nhoff, &protonum);
	if (dataoff <= 0) {
		printk("tcptrack: not prepared to track yet or error occurred\n");
		return;
	}

	th = skb_header_pointer(skb, dataoff, sizeof(_tcph), &_tcph);
	if (th == NULL) {
		printk("tcptack: no tcp hdr \n");
		return;
	}

	printk("Dump %s: skb:0x%p(%d) id:%u %u %pI4:%hu->%pI4:%hu S=%i:%u A=%i:%u %c%c\n",
		   msg,
		   skb,
		   skb->cloned,
		   ntohs(iph->id),
		   protonum,
		   &iph->saddr, ntohs(th->source),
		   &iph->daddr, ntohs(th->dest),
		   (th->syn ? 1 : 0), ntohl(th->seq),
		   (th->ack ? 1 : 0), ntohl(th->ack_seq),
		   (th->fin ? 'F' : ' '), (th->rst ? 'R' : ' '));
}


static bool 
check_zone_id(uint16_t zone_id) 
{
	if (!is_enable_zone_filter()) {
		return true;
	} else if (zone_range[0] <= zone_id && zone_id <= zone_range[1]) {
		return true;
	}

	return false;
}

static void set_ct_timeout(struct net* net, struct nf_conn *ct, enum tcp_conntrack new_state)
{
	unsigned int *timeouts;
	unsigned long timeout;
	struct nf_tcp_net *tn = nf_tcp_pernet(net);

	timeouts = nf_ct_timeout_lookup(ct);
	if (!timeouts)
		timeouts = tn->timeouts;

	timeout = timeouts[new_state];

	__nf_ct_refresh_acct(ct, IP_CT_ESTABLISHED, NULL, timeout, false);
}

static void set_ct_state(struct net* net, struct nf_conn *ct, enum tcp_conntrack new_state) 
{
	enum tcp_conntrack old_state = ct->proto.tcp.state;

	if (old_state == new_state) {
		return;
	}

	ct->proto.tcp.state = new_state;

	set_ct_timeout(net, ct, new_state);
}

//__always_inline static unsigned int
unsigned int
vgw_tcptrack_main(struct net* net, struct sk_buff *skb, struct sw_flow_key *key, struct ovs_conntrack_info *info)
{
	enum ip_conntrack_info ctinfo = 0;
	struct nf_conn *ct = NULL, *lookup_ct = NULL;
	int dataoff;
	u_int8_t protonum;
	const struct iphdr *iph;
	struct iphdr _iph;
	const struct tcphdr *th;
	struct tcphdr _tcph;
	int nhoff, ret=0;
	struct nf_conntrack_zone nf_zone;
	uint32_t last_ack, last_seq;
	u16 family = info->family;
	u16 zone = info->zone.id;

	if (!is_enable_tcp_track()) {
		ret = -1;
		goto out;
	} else if (!check_zone_id(zone)) {
		ret = -2;
		goto out;
	}

	nhoff = skb_network_offset(skb);
	iph = skb_header_pointer(skb, nhoff, sizeof(_iph), &_iph);
	if (!iph) {
		ret = -3;
		goto out;
	}

	dataoff = ipv4_get_l4proto(skb, nhoff, &protonum);
	if (dataoff <= 0) {
		ret = -4;
		goto out;
	} else if (protonum != IPPROTO_TCP) {
		// TCP only
		ret = -5;
		goto out;
	}

	th = skb_header_pointer(skb, dataoff, sizeof(_tcph), &_tcph);
	if (th == NULL) {
		ret = -6;
		goto out;
	} else if (tcp_error(th, skb, dataoff)) {
		ret = -7;
		goto out;
	}

	last_seq = ntohl(th->seq);
	last_ack = ntohl(th->ack_seq);

	ct = get_skb_ct(skb, &ctinfo);
	if (ct == NULL) {
		nf_zone.id = zone;
		nf_zone.dir = NF_CT_DEFAULT_ZONE_DIR;

		// lookup_ct should be released
		lookup_ct = lookup_conntrack_by_skb(net,  &nf_zone, family, skb, false);

		if (lookup_ct == NULL) {
			ret = -8;
			goto out;
		}

		ct = lookup_ct;
	} 

	if (th->syn && ct->proto.tcp.state != TCP_CONNTRACK_ESTABLISHED) {
		enum tcp_conntrack new_state;
		//ct->status |= IPS_CONFIRMED | IPS_ASSURED;
		new_state = TCP_CONNTRACK_SYN_RECV;
		set_ct_state(net, ct, new_state);
	} else if (th->ack && ct->proto.tcp.state < TCP_CONNTRACK_ESTABLISHED) {
		enum tcp_conntrack new_state;
		new_state = TCP_CONNTRACK_ESTABLISHED;
		set_ct_state(net, ct, new_state);
	} else if (th->fin) {
		enum tcp_conntrack new_state = TCP_CONNTRACK_CLOSE_WAIT;
		set_ct_state(net, ct, new_state);
	} else if (th->rst) {
		enum tcp_conntrack new_state = TCP_CONNTRACK_CLOSE;
		set_ct_state(net, ct, new_state);
	} 

	// adjust ovs.ct_state
	if (ctinfo == IP_CT_ESTABLISHED) {
		if (key->ct_state & OVS_CS_F_INVALID) {
			key->ct_state &= ~OVS_CS_F_INVALID;
		}

		if (!(key->ct_state & OVS_CS_F_ESTABLISHED)) {
			key->ct_state |= OVS_CS_F_ESTABLISHED;
		}
	}

	if (last_seq == ct->proto.tcp.last_seq &&
		last_ack == ct->proto.tcp.last_ack) {

		//pr_info("vgw_tcptrack_main: found ct with the same seq and skip, seq=%u:%u, ack=%u:%u \n", 
		//		 ct->proto.tcp.last_seq, last_seq, ct->proto.tcp.last_ack, last_ack);

		ret = -10;
		goto out;
	}

	if (is_enable_dump_packet()) {
		dump_skb_ct((const struct sk_buff *)skb, ct, ctinfo, zone, key);
	}

	/////////////////////
	spin_lock_bh(&ct->lock);

	// XXX: set seq/ack
	ct->proto.tcp.last_seq = last_seq;
	ct->proto.tcp.last_end = segment_seq_plus_len(last_seq, skb->len, dataoff, th);
	if (last_ack != 0) {
		ct->proto.tcp.last_ack = last_ack;
	}

	//dump_ip_tuple(ct, ctinfo, th);

	spin_unlock_bh(&ct->lock);
	////////////////////////////

out:
	// release ct
	if (lookup_ct) {
		nf_ct_put(lookup_ct);
	}

	if (is_enable_dump_packet() && ret != -10) {
		pr_info("done vgw_tcptrack_main: ret=%d \n", ret);
	}

	return 0;
}

/////////////////////////////
#if 0
// use kprobe instead of bpf

/* Begin kfunc definitions */

__diag_push();
__diag_ignore_all("-Wmissing-prototypes", "Global kfuncs as their definitions will be in BTF");

__bpf_kfunc int bpf_vgw_update_tcp_ct(struct net* net, struct sk_buff *skb, u16 family, u16 zone)
{
	vgw_tcptrack_main(net, skb, family, zone);
	return 0;
}

/* End kfunc definitions */

__diag_pop()

BTF_SET8_START(nf_ct_kfunc_set_vgw)
BTF_ID_FLAGS(func, bpf_vgw_update_tcp_ct)
BTF_SET8_END(nf_ct_kfunc_set_vgw)

static const struct btf_kfunc_id_set vgw_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &nf_ct_kfunc_set_vgw,
};

int register_nf_conntrack_bpf(void)
{
	int ret;

	//ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &vgw_kfunc_set);
	//ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &vgw_kfunc_set);
	//ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS, &vgw_kfunc_set);
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &vgw_kfunc_set);
	//ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING, &vgw_kfunc_set);
	if (!ret) {
		pr_info("tcptack: register bpf succeeded \n");
	} else {
		pr_err("tcptack: failed to register bpf, ret=%d \n", ret);
	}

	return ret;
}

void cleanup_nf_conntrack_bpf(void)
{

}
#endif

int vgw_tcptrack_init(void) 
{
	pr_info("Init VGW tcptrack Module: %s\n", VERSION_STRING);

	//register_nf_conntrack_bpf();
	kprobe_init();

	return 0;
}

void vgw_tcptrack_exit(void)
{
	pr_info("Exit VGW tcptrack Module: %s\n", VERSION_STRING);

	//cleanup_nf_conntrack_bpf();
	kprobe_exit();
}

