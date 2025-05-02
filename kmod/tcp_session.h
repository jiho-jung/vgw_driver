#ifndef _TCP_SESSION_H
#define _TCP_SESSION_H


#define FLAGS_TCP_TRACK				0x01
#define FLAGS_ZONE_FILTER			0x02
#define FLAGS_EXPORT_TCP_TRACK		0x04
#define FLAGS_DUMP_PKT				0x08


extern uint32_t tcptrack_flags;
static inline bool is_enable_tcp_track(void) {
	return !!(tcptrack_flags & FLAGS_TCP_TRACK);
}

static inline bool is_enable_zone_filter(void) {
	return !!(tcptrack_flags & FLAGS_ZONE_FILTER);
}

static inline bool is_enable_export_tcp_track(void) {
	return !!(tcptrack_flags & FLAGS_EXPORT_TCP_TRACK);
}

static inline bool is_enable_dump_packet(void) {
	return !!(tcptrack_flags & FLAGS_DUMP_PKT);
}

//int vgw_update_tcp_state(struct nf_conn *ct);
int vgw_dump_tcp_protoinfo(struct sk_buff *skb, struct nf_conn *ct, bool destroy);

#endif
