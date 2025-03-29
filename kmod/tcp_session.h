#ifndef _TCP_SESSION_H
#define _TCP_SESSION_H

int vgw_update_tcp_state(struct nf_conn *ct);
int vgw_dump_tcp_protoinfo(struct sk_buff *skb, struct nf_conn *ct, bool destroy);

#endif
