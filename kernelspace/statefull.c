#include "statefull.h"

bool is_tcp(struct sk_buff* skb) {
	struct iphdr* ip_header = (struct iphdr*) skb_network_header(skb);
	return (ip_header->protocol == PROT_TCP);
}

bool isProxy(struct sk_buff* skb) {
	struct iphdr* ip_header = (struct iphdr*) skb_network_header(skb);
	struct tcphdr* tcp_header = (struct tcphdr*)((char*)ip_header + (ip_header->ihl * 4));

	bool is_smtp = tcp_header->source == PORT_SMTP || tcp_header->dest == PORT_SMTP;
	bool is_http = tcp_header->source == PORT_HTTP || tcp_header->dest == PORT_HTTP;
	bool is_orientdb = tcp_header->source == PORT_ORIENTDB || tcp_header->dest == PORT_ORIENTDB;

	return is_smtp || is_http || is_orientdb;
}


bool isSynNoAck(struct sk_buff* skb) {
	struct iphdr* ip_header = (struct iphdr*) skb_network_header(skb);
	struct tcphdr* tcp_header = (struct tcphdr*)((char*)ip_header + (ip_header->ihl * 4));

	return (tcp_header->syn && !tcp_header->ack);
}


void add_proxy_port(ConnectionRow* connection, struct tcphdr* tcp_header) {
	if (tcp_header->source == PORT_SMTP || tcp_header->dest == PORT_SMTP)
		connection->proxy_as_server_port = PORT_PROXY_SMTP;
	else if (tcp_header->source == PORT_HTTP || tcp_header->dest == PORT_HTTP)
		connection->proxy_as_server_port = PORT_PROXY_HTTP;
	else if (tcp_header->source == PORT_ORIENTDB || tcp_header->dest == PORT_ORIENTDB)
		connection->proxy_as_server_port = PORT_PROXY_ORIENTDB;
	else {
		printk(KERN_ERR "ERROR: tried to add proxy port to packet without special port\n");
	}
}

__u8 tcp_state_machine(ConnectionRow* connection, ConnectionSide* source,
		struct tcphdr* tcp_header, ConnectionSide* init, prot_state_t* state) {
	printk(KERN_INFO "syn = %u, ack = %u, rst = %u, fin = %u\n",
			tcp_header->syn, tcp_header->ack, tcp_header->rst, tcp_header->fin);
	if (tcp_header->rst) {
		// close connection immediately. the row will eventually be deleted by timeout
		*state = TCP_CLOSED;
		connection->last_updated = get_time();
		return NF_ACCEPT;
	}

	switch(*state) {
	case TCP_NO_CONNECTION:
		// waiting for initalize syn
		if (*source == *init) {
			if (tcp_header->syn && !tcp_header->ack) {
				*state = TCP_OPEN_SYN_SENT;
				connection->last_updated = get_time();
				return NF_ACCEPT;
			}
		}
		return NF_DROP;

	case TCP_OPEN_SYN_SENT:
		// waiting to syn-ack from react side
		if (*source != *init) {
			if (tcp_header->syn && tcp_header->ack) {
				*state = TCP_OPEN_SYN_ACK_SENT;
				connection->last_updated = get_time();
				return NF_ACCEPT;
			}
		}
		return NF_DROP;

	case TCP_OPEN_SYN_ACK_SENT:
		// waiting to ack from init side
		if (*source == *init) {
			if (tcp_header->ack) {
				*state = TCP_IS_ESTABLISHED;
				connection->last_updated = get_time();
				printk(KERN_INFO "OPENNING: got ack packet from init - established connection\n");
				return NF_ACCEPT;
			}
		}
		return NF_DROP;

	case TCP_IS_ESTABLISHED:
		if (tcp_header->fin) {
			*state = TCP_CLOSE_FIN_SENT;
			// chose init to be the source of fin message
			*init = *source;
		}
		connection->last_updated = get_time();
		return NF_ACCEPT;

	case TCP_CLOSE_FIN_SENT:
		// waiting to fin-ack or only ack from react side
		if (*source != *init) {
			if (tcp_header->ack && !tcp_header->fin) {
				*state = TCP_CLOSE_ONLY_ACK_SENT;
				connection->last_updated = get_time();
				return NF_ACCEPT;
			}
			else if (tcp_header->ack && tcp_header->fin) {
				*state = TCP_CLOSE_FIN_ACK_SENT;
				connection->last_updated = get_time();
				return NF_ACCEPT;
			}
		}
		return NF_DROP;

	case TCP_CLOSE_ONLY_ACK_SENT:
		// react sent ack, now waiting for fin from react side
		if (*source != *init) {
			if (tcp_header->fin) {
				*state = TCP_CLOSE_FIN_ACK_SENT;
			}
		}
		connection->last_updated = get_time();
		return NF_ACCEPT;

	case TCP_CLOSE_FIN_ACK_SENT:
		// waiting to final ack from init side
		if (*source == *init) {
			if (tcp_header->ack) {
				// close connection. the row will eventually be deleted by timeout
				printk(KERN_INFO "CLOSING: got ack packet from init - closing connection\n");
				*state = TCP_CLOSED;
				connection->last_updated = get_time();
				return NF_ACCEPT;
			}
		}
		return NF_DROP;

	default: // connection closed
		return NF_DROP;
	}

}

ConnectionResult check_connections(struct sk_buff* skb, bool proxy, SEARCH_MODE mode) {
	struct iphdr* ip_header = (struct iphdr*) skb_network_header(skb);
	struct tcphdr* tcp_header = (struct tcphdr*)((char*)ip_header + (ip_header->ihl * 4));
	ConnectionAndSide conn_and_side = get_connection(ip_header->saddr, tcp_header->source,
			ip_header->daddr, tcp_header->dest, mode);
	ConnectionRow* connection = conn_and_side.connection;
	ConnectionSide source = conn_and_side.side;

	if (connection == NULL || source == SIDE_INVALID) // connection not found
		return (ConnectionResult) {ACTION_NOT_DECIDED, NULL, SIDE_INVALID};

	ConnectionSide *init;
	prot_state_t *state;

	if (!proxy) {
		state = &connection->regular_state;
		init = &connection->reular_init;
	}
	else {
		if (source == SIDE_CLIENT || source == SIDE_PROXY_SERVER) {
			state = &connection->proxy_to_client_state;
			init = &connection->proxy_to_client_init;
		}
		else { // source == SIDE_SERVER or source == SIDE_PROXY_CLIENT
			state = &connection->proxy_to_server_state;
			init = &connection->proxy_to_server_init;
		}
	}
	__u8 action = tcp_state_machine(connection, &source, tcp_header, init, state);

	return (ConnectionResult) {action, connection, source};
}


ConnectionRow* create_connection(struct sk_buff *skb, bool for_proxy) {
	struct iphdr* ip_header = (struct iphdr*) skb_network_header(skb);
	if (ip_header->protocol != PROT_TCP) {
		printk(KERN_ERR "ERROR: tried to create connection non tcp\n");
		return false;
	}
	struct tcphdr* tcp_header = (struct tcphdr*)((char*)ip_header + (ip_header->ihl * 4));
	if (tcp_header->ack) {
		printk(KERN_ERR "ERROR: tried to create connection with ack packet\n");
		return false;
	}
	ConnectionRow* conn = add_connection(ip_header->saddr, tcp_header->source,
			ip_header->daddr, tcp_header->dest);

	if (conn == NULL) return NULL;

	if (!for_proxy)
		conn->regular_state = TCP_OPEN_SYN_SENT;
	else {
		conn->proxy_to_client_state = TCP_OPEN_SYN_SENT;
		add_proxy_port(conn, tcp_header);
	}

	return conn;
}


void forge_connection(struct sk_buff* skb, ConnectionResult connectionResult, const struct net_device *in, const struct net_device *out) {

	struct iphdr* ip_header = (struct iphdr*) skb_network_header(skb);
	struct tcphdr* tcp_header = (struct tcphdr*)((char*)ip_header + (ip_header->ihl * 4));

	ConnectionRow* connection = connectionResult.connection;
	if (connectionResult.source == SIDE_CLIENT || connectionResult.source == SIDE_SERVER) {
		// pre packet, from C-S, forge ip destination to local network
		if (strcmp(in->name, IN_NET_DEVICE_NAME) == 0)
			ip_header->daddr = OUT_NET_IP_ADDR; // 10.1.1.3
		else
			ip_header->daddr = IN_NET_IP_ADDR; // 10.1.2.3
	}
	switch(connectionResult.source) {
	case SIDE_CLIENT:
		// C->S: convert destination from server to proxy as server
		tcp_header->dest = connection->proxy_as_server_port;
		break;

	case SIDE_SERVER:
		// S->C: convert destination from client to proxy as client
		tcp_header->dest = connection->proxy_as_client_port;
		break;

	case SIDE_PROXY_CLIENT:
		// PC->S: forge source from proxy as client to client
		ip_header->saddr   = connection->client_ip;
		tcp_header->source = connection->client_port;
		break;

	case SIDE_PROXY_SERVER:
		// PS->C: forge source from proxy as server to server
		ip_header->saddr   = connection->server_ip;
		tcp_header->source = connection->server_port;
		break;

	default:
		printk(KERN_ERR "ERROR: Tried to forge invalid side\n");
		return;
	}

	// handle checksum
	skb_linearize(skb);
	ip_header = (struct iphdr*) skb_network_header(skb);
	tcp_header = (struct tcphdr*)((char*)ip_header + (ip_header->ihl * 4));

	int tcplen = (skb->len - ((ip_header->ihl )<< 2));
	tcp_header->check=0;
	tcp_header->check = tcp_v4_check(tcplen,ip_header->saddr, ip_header->daddr,
			csum_partial((char*)tcp_header, tcplen,0));
	skb->ip_summed = CHECKSUM_NONE; //stop offloading
	ip_header->check = 0;
	ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);
}


__u8 checkPacketPre(struct sk_buff* skb, const struct net_device *in, const struct net_device *out) {

	struct iphdr* ip_header = (struct iphdr*) skb_network_header(skb);
	struct tcphdr* tcp_header = (struct tcphdr*)((char*)ip_header + (ip_header->ihl * 4));
	printk("got PRE packet from ip %u, port %u to ip %u port %u\n",
			ip_header->saddr, ntohs(tcp_header->source), ip_header->daddr, ntohs(tcp_header->dest));

	if (!is_tcp(skb)) {
		RuleResult rr = checkPacketRules(skb, in, out);
		// send log
		add_log(skb, NF_INET_PRE_ROUTING, rr);
		// return action
		return rr.action;
	}

	// is tcp - search in connection
	bool proxy = isProxy(skb);
	ConnectionResult connectionResult = check_connections(skb, proxy, SERACH_BY_C_S);
	if (connectionResult.action != ACTION_NOT_DECIDED) { // get connection and action
		// send to log
		RuleResult rr = {connectionResult.action, REASON_CONNECTION};
		add_log(skb, NF_INET_PRE_ROUTING, rr);
		if (proxy && connectionResult.action == NF_ACCEPT) {
			// convert dst to proxy
			forge_connection(skb, connectionResult, in, out);
		}
		// return action
		return connectionResult.action;
	}

	// ACTION_NOT_DECIDED - connection not found
	if (isSynNoAck(skb)) {
		// trying to create new connection - check in rules if allowed
		RuleResult rr = checkPacketRules(skb, in, out);
		add_log(skb, NF_INET_PRE_ROUTING, rr);
		if (rr.action == NF_ACCEPT) {
			// add new connection
			ConnectionRow* new_conn = create_connection(skb, proxy);
			if (proxy) {
				// source of first packet in connection always client
				ConnectionResult res = {NF_ACCEPT, new_conn, SIDE_CLIENT};
				// convert dst to proxy
				forge_connection(skb, res, in, out);
			}
		}
		return rr.action;
	}

	// connection not found and isn't start of new connection - drop
	add_log(skb, NF_INET_PRE_ROUTING, (RuleResult) {NF_DROP, REASON_CONNECTION});

	return NF_DROP;
}


__u8 checkPacketLocalOut(struct sk_buff* skb, const struct net_device *in, const struct net_device *out) {
	if (!is_tcp(skb)) return NF_DROP;

	struct iphdr* ip_header = (struct iphdr*) skb_network_header(skb);
	struct tcphdr* tcp_header = (struct tcphdr*)((char*)ip_header + (ip_header->ihl * 4));
	printk("got LOCAL_OUT packet from ip %u, port %u to ip %u port %u\n",
			ip_header->saddr, ntohs(tcp_header->source), ip_header->daddr, ntohs(tcp_header->dest));

	// if tcp - assume it proxy connection
	ConnectionResult connectionResult = check_connections(skb, true, SEARCH_BY_PROXY);
	__u8 action = (connectionResult.action == NF_ACCEPT) ? NF_ACCEPT : NF_DROP;
	if (action == NF_ACCEPT) {
		// forge packet source from client/server
		forge_connection(skb, connectionResult, in, out);
	}
	// add log
	add_log(skb, NF_INET_LOCAL_OUT, (RuleResult) {action ,REASON_CONNECTION});
	
	return action;
}
