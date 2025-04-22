#ifndef VGW_NL_CT_H
#define VGW_NL_CT_H

#include <linux/netlink.h>

#ifndef __KERNEL__
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#endif

#define VGW_NL_CT_FAMILY_NAME		"vgw_nl_ct" // max 16 char

#if 0
#define VGW_NL_CT_MCGRP0_NAME		"vgw_nl_mcgrp0"
#define VGW_NL_CT_MCGRP1_NAME		"vgw_nl_mcgrp1"
#define VGW_NL_CT_MCGRP2_NAME		"vgw_nl_mcgrp2"
#endif

#define VGW_NL_CT_ATTR_MSG_MAX		256

enum {
	VGW_NL_CT_CMD_UNSPEC,		// Must NOT use element 0
	VGW_NL_CT_CMD_DUMP,
};

#if 0
enum vgw_nl_multicast_groups {
	VGW_NL_CT_MCGRP0,
	VGW_NL_CT_MCGRP1,
	VGW_NL_CT_MCGRP2,
};
#define VGW_NL_CT_MCGRP_MAX		3

static char* vgw_nl_mcgrp_names[VGW_NL_CT_MCGRP_MAX] = {
	VGW_NL_CT_MCGRP0_NAME,
	VGW_NL_CT_MCGRP1_NAME,
	VGW_NL_CT_MCGRP2_NAME,
};
#endif

enum vgw_nl_ct_attrs {
	VGW_NL_CT_ATTR_UNSPEC,		// Must NOT use element 0

	VGW_NL_CT_ATTR_ZONE,

	__VGW_NL_CT_ATTR__MAX,
};
#define VGW_NL_CT_ATTR_MAX (__VGW_NL_CT_ATTR__MAX - 1)


#endif
