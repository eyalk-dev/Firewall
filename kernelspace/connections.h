#ifndef CONNECTIONS_H_
#define CONNECTIONS_H_

#include <linux/list.h>
#include <linux/time.h>
#include <stdbool.h>
#include "fw.h"
#include "utils.h"

typedef enum {
	TCP_NO_CONNECTION = 0,
	TCP_OPEN_SYN_SENT = 1,
	TCP_OPEN_SYN_ACK_SENT = 2,
	TCP_IS_ESTABLISHED = 3,
	TCP_CLOSE_FIN_SENT = 4,
	TCP_CLOSE_ONLY_ACK_SENT = 5,
	TCP_CLOSE_FIN_ACK_SENT = 6,
	TCP_CLOSED = 7,
} prot_state_t;

typedef enum { // source of packet
	SIDE_CLIENT = 0,
	SIDE_SERVER = 1,
	SIDE_PROXY_CLIENT = 2,
	SIDE_PROXY_SERVER = 3,
	SIDE_INVALID = 4,
} ConnectionSide;

typedef enum {
	SERACH_BY_C_S,
	SEARCH_BY_PROXY,
} SEARCH_MODE;

typedef struct {
	__be32	client_ip;
	__be16	client_port;

	__be32	server_ip;
	__be16	server_port;

	__be16	proxy_as_server_port;
	__be16	proxy_as_client_port;

	prot_state_t regular_state;
	ConnectionSide reular_init;

	prot_state_t proxy_to_server_state;
	ConnectionSide proxy_to_server_init;

	prot_state_t proxy_to_client_state;
	ConnectionSide proxy_to_client_init;

	__kernel_time_t last_updated;
	struct list_head list;
} ConnectionRow;

typedef struct {
	ConnectionRow*	connection;
	ConnectionSide	side;
} ConnectionAndSide;

typedef struct {
	__u8 			action;
	ConnectionRow*	connection;
	ConnectionSide	source;
} ConnectionResult;

/**
 * get client & server address
 * add appropriate connection to table
 * @ret &connection if allocation succeeded, else null
 */
ConnectionRow* add_connection(__be32 client_ip, __u16  client_port,
		__be32 server_ip, __u16  server_port);

/**
 * get client & server address, and search mode
 * @ret found connection and its side, or invalid connection and side if not found
 */
ConnectionAndSide get_connection(__be32 src_ip, __u16  src_port,
		__be32 dst_ip, __u16  dst_port, SEARCH_MODE mode);


/**
 * sysfs - show connections table
 */
ssize_t display_connections_table(struct device *dev, struct device_attribute *attr, char *buf);

/**
 * sysfs writing - allowing following actions on connection:
 * 1. get client & server address, and add proxy as client to this connection
 * 2. get client & server address, and add new ftp-data connection with these args
 * @ret count if success, else according error value
 */
ssize_t actions_on_connection(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

/** clear connection */
ssize_t clear_connections(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

/**
 * create char device "fw_conn",
 * use given sysfs_class and create sysfs class and attributes for rules
 * @ret - 0 for success, -1 for failure
 */
int init_hw4_connections(struct class* sysfs_class_input);

/** destory char device "fw_conn" and its sysfs*/
void exit_hw4_connections(void);


#endif /* CONNECTIONS_H_ */
