#ifndef COMPATIBILITY_H
#define COMPATIBILITY_H

//////////////////
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


//////////////////
// openvswitch

#define CTNL_TIMEOUT_NAME_MAX	32
#define OVS_CT_LABELS_LEN_32	4
#define OVS_CT_LABELS_LEN	(OVS_CT_LABELS_LEN_32 * sizeof(__u32))
struct ovs_key_ct_labels {
	union {
		__u8	ct_labels[OVS_CT_LABELS_LEN];
		__u32	ct_labels_32[OVS_CT_LABELS_LEN_32];
	};
};

struct ovs_ct_len_tbl {
	int maxlen;
	int minlen;
};

/* Metadata mark for masked write to conntrack mark */
struct md_mark {
	u32 value;
	u32 mask;
};

/* Metadata label for masked write to conntrack label. */
struct md_labels {
	struct ovs_key_ct_labels value;
	struct ovs_key_ct_labels mask;
};

enum ovs_ct_nat {
	OVS_CT_NAT = 1 << 0,     /* NAT for committed connections only. */
	OVS_CT_SRC_NAT = 1 << 1, /* Source NAT for NEW connections. */
	OVS_CT_DST_NAT = 1 << 2, /* Destination NAT for NEW connections. */
};

struct nf_nat_range2 {
	unsigned int			flags;
	union nf_inet_addr		min_addr;
	union nf_inet_addr		max_addr;
	union nf_conntrack_man_proto	min_proto;
	union nf_conntrack_man_proto	max_proto;
	union nf_conntrack_man_proto	base_proto;
};

/* Conntrack action context for execution. */
struct ovs_conntrack_info {
	struct nf_conntrack_helper *helper;
	struct nf_conntrack_zone zone;
	struct nf_conn *ct;
	u8 commit : 1;
	u8 nat : 3;                 /* enum ovs_ct_nat */
	u8 force : 1;
	u8 have_eventmask : 1;
	u16 family;
	u32 eventmask;              /* Mask of 1 << IPCT_*. */
	struct md_mark mark;
	struct md_labels labels;
	char timeout[CTNL_TIMEOUT_NAME_MAX];
	struct nf_ct_timeout *nf_ct_timeout;
	struct nf_nat_range2 range;  /* Only present for SRC NAT and DST NAT. */
};

#endif
