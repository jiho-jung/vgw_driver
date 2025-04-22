#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/export.h>
#include <net/genetlink.h>

#include "vgw_netlink.h"
#include "vgw_version.h"

// https://www.electronicsfaq.com/2014/02/generic-netlink-sockets-example-code.html

static struct genl_family vgw_nl_family;

#if 0
static void greet_group(unsigned int group)
{	
	void *hdr;
	int res, flags = GFP_ATOMIC;
	char msg[VGW_NL_CT_ATTR_MSG_MAX];
	struct sk_buff* skb = genlmsg_new(NLMSG_DEFAULT_SIZE, flags);

	if (!skb) {
		printk(KERN_ERR "%d: OOM!!", __LINE__);
		return;
	}

	hdr = genlmsg_put(skb, 0, 0, &vgw_nl_family, flags, VGW_NL_CT_CMD_DUMP);
	if (!hdr) {
		printk(KERN_ERR "%d: Unknown err !", __LINE__);
		goto nlmsg_fail;
	}

	snprintf(msg, VGW_NL_CT_ATTR_MSG_MAX, "Hello group %s\n",
			genl_test_mcgrp_names[group]);

	res = nla_put_string(skb, VGW_NL_CT_ATTR_ZONE, msg);
	if (res) {
		printk(KERN_ERR "%d: err %d ", __LINE__, res);
		goto nlmsg_fail;
	}

	genlmsg_end(skb, hdr);
	genlmsg_multicast(&vgw_nl_family, skb, 0, group, flags);
	return;

nlmsg_fail:
	genlmsg_cancel(skb, hdr);
	nlmsg_free(skb);
	return;
}
#endif

int dump_conntrack(struct sk_buff *skb_2, struct genl_info *info) 
{
	//struct nlattr *na;
	struct sk_buff *skb;
	int rc;
	void *msg_head;
	char msg[VGW_NL_CT_ATTR_MSG_MAX];

	if (info == NULL) {
		goto out;
	}

	//Send a message back
	//Allocate some memory, since the size is not yet known use NLMSG_GOODSIZE
	skb = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (skb == NULL) {
		goto out;
	}

	//Create the message headers
	msg_head = genlmsg_put(skb, 0, info->snd_seq, &vgw_nl_family, 0, VGW_NL_CT_CMD_DUMP);
	if (msg_head == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	snprintf(msg, VGW_NL_CT_ATTR_MSG_MAX, "Hello sender %d", info->snd_portid);

	rc = nla_put_string(skb, VGW_NL_CT_CMD_DUMP, msg);
	if (rc != 0) {
		goto out;
	}

	//Finalize the message
	genlmsg_end(skb, msg_head);

	//Send the message back
	rc = genlmsg_unicast(genl_info_net(info), skb, info->snd_portid);
	if (rc != 0) {
		goto out;
	}

	return 0;

out:
	printk("An error occured in dump_conntrack:\n");
	return 0;
}


static int genl_test_rx_msg(struct sk_buff* skb, struct genl_info* info)
{
	if (!info->attrs[VGW_NL_CT_ATTR_ZONE]) {
		printk("empty message from %d!!\n", info->snd_portid);
		printk("%p\n", info->attrs[VGW_NL_CT_ATTR_ZONE]);
		return -EINVAL;
	}

	//printk("port=%u,  zone=%s, seq=%u \n", info->snd_portid, (char*)nla_data(info->attrs[VGW_NL_CT_ATTR_ZONE]), info->snd_seq);
	printk("port=%u,  zone=%u, seq=%u \n", info->snd_portid, nla_get_u32(info->attrs[VGW_NL_CT_ATTR_ZONE]), info->snd_seq);

	dump_conntrack(skb, info);

	return 0;
}

static struct nla_policy vgw_nl_ct_policy[VGW_NL_CT_ATTR_MAX+1] = {
	[VGW_NL_CT_ATTR_ZONE] = {
		.type = NLA_U32,
#if 0
#ifdef __KERNEL__
		.len = 4
#else
		.maxlen = 4
#endif
#endif
	},
};

static const struct genl_ops genl_test_ops[] = {
	{
		.cmd = VGW_NL_CT_CMD_DUMP,
		.policy = vgw_nl_ct_policy,
		.doit = genl_test_rx_msg,
		.dumpit = NULL,
	},
};

#if 0
static const struct genl_multicast_group genl_test_mcgrps[] = {
	[GENL_TEST_MCGRP0] = { .name = GENL_TEST_MCGRP0_NAME, },
	[GENL_TEST_MCGRP1] = { .name = GENL_TEST_MCGRP1_NAME, },
	[GENL_TEST_MCGRP2] = { .name = GENL_TEST_MCGRP2_NAME, },
};
#endif

static struct genl_family vgw_nl_family = {
	.name = VGW_NL_CT_FAMILY_NAME,
	.version = 1,
	//.maxattr = VGW_NL_CT_ATTR_MSG_MAX,
	.maxattr = VGW_NL_CT_ATTR_MAX,
	.netnsok = false,
	.module = THIS_MODULE,
	.ops = genl_test_ops,
	.n_ops = ARRAY_SIZE(genl_test_ops),

	//.mcgrps = genl_test_mcgrps,
	//.n_mcgrps = ARRAY_SIZE(genl_test_mcgrps),
};

int genl_test_init(void)
{
	int rc;

	pr_info("Init VGW Netlink Module: %s\n", VERSION_STRING);

	rc = genl_register_family(&vgw_nl_family);
	if (rc)
		goto failure;

	return 0;

failure:

	printk("VGE Netlink: error occurred in %s\n", __func__);
	return -EINVAL;
}

void genl_test_exit(void)
{
	pr_info("Exit VGW Netlink Module: %s\n", VERSION_STRING);
	genl_unregister_family(&vgw_nl_family);
}

