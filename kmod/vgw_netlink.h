#ifndef VGW_NL_CT_H
#define VGW_NL_CT_H

#include <linux/netlink.h>

#ifndef __KERNEL__
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#endif

#define VGW_NL_CT_FAMILY_NAME		"vgw_nl_ct" // max 16 char

enum {
	VGW_NL_CT_CMD_UNSPEC,		// Must NOT use element 0
	VGW_NL_CT_CMD_DUMP,
};

enum vgw_nl_ct_attrs {
	VGW_NL_CT_ATTR_UNSPEC,		// Must NOT use element 0

	VGW_NL_CT_ATTR_FILTER,
	VGW_NL_CT_ATTR_TCP_SEQ,

	__VGW_NL_CT_ATTR__MAX,
};
#define VGW_NL_CT_ATTR_MAX (__VGW_NL_CT_ATTR__MAX - 1)


#endif
