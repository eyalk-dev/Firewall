#ifndef STATEFULL_H_
#define STATEFULL_H_

#include "fw.h"
#include "utils.h"
#include <net/tcp.h>
#include "connections.h"
#include "rules.h"
#include "logs.h"

bool is_tcp(struct sk_buff* skb);

bool isProxy(struct sk_buff* skb);

bool isSynNoAck(struct sk_buff* skb);


/**
 * get new created proxy connection, and tcp_header of first packet
 * add proxy as server port, according to type (http or ftp)
 */
void add_proxy_port(ConnectionRow* connection, struct tcphdr* tcp_header);

/**
 * tcp state machine for each connection:
 * get connection, pointer to relevant state, side of checked packet,
 * init side of relevant connection, and tcp header of checked packet.
 *
 * check args to see how packet behaving according to tcp state machine (rst, handshakes, etc).
 * update connection state accordingly, and @ret if accept or drop packet
 */
__u8 tcp_state_machine(ConnectionRow* connection, ConnectionSide* source,
		struct tcphdr* tcp_header, ConnectionSide* init, prot_state_t* state);

/**
 * get skb and search mode to check if packet fit for existing connection.
 * if so, check packet in tcp machine and return result
 * @ret action (could be undecided), connection, and source side
 */
ConnectionResult check_connections(struct sk_buff* skb, bool proxy, SEARCH_MODE mode) ;

/**
 * create new connection and return it according to it's skb values
 */
ConnectionRow* create_connection(struct sk_buff *skb, bool for_proxy);

/**
 * forge connection for proxy:
 * when sent from client/server - forging destination to proxy as server/client
 * forging source to proxy as client/server - forging source to client/server
 */
void forge_connection(struct sk_buff* skb, ConnectionResult connectionResult, const struct net_device *in, const struct net_device *out);

/**
 * after basic filtering, check all packets captures at pre routing
 * search in existing connections, rules and tcp state to decide what to do with if
 * if accepted and proxy - forge
 * @ret action - accept or drop
 */
__u8 checkPacketPre(struct sk_buff* skb, const struct net_device *in, const struct net_device *out);

/**
 * after basic filtering, check all packets captures at local out (assume from proxy)
 * search in existing connections, and tcp state to decide what to do with if
 * if accepted - forge
 * @ret action - accept or drop
 */
__u8 checkPacketLocalOut(struct sk_buff* skb, const struct net_device *in, const struct net_device *out);




#endif /* STATEFULL_H_ */
