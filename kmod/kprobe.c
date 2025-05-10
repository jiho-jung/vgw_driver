#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>

#include "flow.h"
#include "compatibility.h"

struct func_args {
    struct net *net;
    struct sk_buff *skb;
    struct sw_flow_key *key;
    struct ovs_conntrack_info *info;
    //uint16_t family;
    //uint16_t zone;
};

//#define USE_KPROBE 1

extern unsigned int vgw_tcptrack_main(struct net* net, struct sk_buff *skb, struct sw_flow_key *key, struct ovs_conntrack_info *info);
extern void dump_skb(char *msg, const struct sk_buff *skb) ;

////////////////////////
// order of running handlers

#if 0
kretprobe entry handler
kprobe pre handler
kprobe post handler
kretprobe return handler
#endif

#ifdef USE_KPROBE
static int kprobe_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    //pr_debug("run kprobe pre handler: kp=0x%p \n", p);
    return 0;
}
 
static void kprobe_post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    //pr_debug("run kprobe post handler: kp=0x%p \n", p);
}
 
static struct kprobe kp = {
        .symbol_name = "ovs_ct_execute",
        .pre_handler = kprobe_pre_handler,
        .post_handler = kprobe_post_handler,
};
#endif

static int kretprobe_return_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    unsigned long retval = 0;
    struct func_args *args = (struct func_args*)ri->data;

    // only available 0
    retval = regs_return_value(regs);
    if (retval) {
        return 0;
    } else if (args->key->recirc_id != 0) {
        // XXX: recursively call
        return 0;
    }

    vgw_tcptrack_main(args->net, args->skb, args->key, args->info);

#if 0
    pr_info("run kretprobe return handler: ret_val=%lu, skb=0x%p, zone=%d, ct_state=0x%x, commit=%d \n", 
            retval, args->skb, args->info->zone.id, args->key->ct_state, args->info->commit);
#endif

    return 0;
}

static int kretprobe_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct func_args *args = (struct func_args*)ri->data;
    struct net *net;
    struct sk_buff *skb;
    struct sw_flow_key *key;
    struct ovs_conntrack_info *info;

    // XXX: store function args
    //int ovs_ct_execute(struct net *net, struct sk_buff *skb, struct sw_flow_key *key, const struct ovs_conntrack_info *info)
    net = (struct net *)regs->di;
    skb = (struct sk_buff *)regs->si;
    info = (struct ovs_conntrack_info *)regs->cx;
    key = (struct sw_flow_key *)regs->dx;

    args->net = net;
    args->skb = skb;
    args->key = key;
    args->info = info;
    //args->family = info->family;
    //args->zone = info->zone.id;

#if 0
    dump_skb("kretprobe entry", (const struct sk_buff *)skb);
    pr_info("run kretprobe entry: key.recirc_id=%u \n", key->recirc_id);
#endif

    return 0;
}
 
struct kretprobe kr = { 
        .kp.symbol_name = "ovs_ct_execute",
        .data_size = sizeof(struct func_args),
        .handler = kretprobe_return_handler,
        .entry_handler = kretprobe_entry_handler,
        //.maxactive = 32,
};

int kprobe_init(void)
{
    int ret;

#ifdef USE_KPROBE
    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("register_kprobe failed, returned %d\n", ret);
        return ret;
    }

    pr_info("registered kprobe at %p\n", kp.addr);
#endif

    ret = register_kretprobe(&kr);
    if (ret < 0) {
        pr_err("register_kretprobe failed, returned %d\n", ret);
        return ret;
    }

    pr_info("kretprobe registered.\n");

    return 0;
}

void  kprobe_exit(void)
{
    unregister_kretprobe(&kr);
    pr_info("kretprobe unregistered\n");

#ifdef USE_KPROBE
    unregister_kprobe(&kp);
    pr_info("unregistered kprobe at %p\n", kp.addr);
#endif

}

