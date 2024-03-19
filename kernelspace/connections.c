#include "connections.h"

static int major_number;
static struct class* sysfs_class = NULL;
static struct device* sysfs_device = NULL;

static LIST_HEAD(connection_list);

ConnectionRow* add_connection(__be32 client_ip, __u16  client_port,
		__be32 server_ip, __u16  server_port) {
	// add first side
	ConnectionRow* new_connection = kmalloc(sizeof(ConnectionRow), GFP_ATOMIC);
	if (!new_connection) {
		printk(KERN_ERR "allocation failed\n");
		return NULL;
	}
	new_connection->last_updated = get_time();
	new_connection->client_ip   = client_ip;
	new_connection->client_port = client_port;
	new_connection->server_ip   = server_ip;
	new_connection->server_port = server_port;
	new_connection->regular_state = TCP_NO_CONNECTION;
	new_connection->reular_init = SIDE_CLIENT;
	new_connection->proxy_to_client_state = TCP_NO_CONNECTION;
	new_connection->proxy_to_client_init = SIDE_CLIENT;
	new_connection->proxy_to_server_state = TCP_NO_CONNECTION;
	new_connection->proxy_to_server_init = SIDE_PROXY_CLIENT;
	list_add(&new_connection->list, &connection_list);
	return new_connection;
}

static void delete_connection(ConnectionRow* conn) {
	list_del(&conn->list); // remove from list
	kfree(conn); // free memory
}


ConnectionAndSide get_connection(__be32 src_ip, __u16  src_port,
		__be32 dst_ip, __u16  dst_port, SEARCH_MODE mode)
{
	ConnectionRow *conn, *next_conn;
	__kernel_time_t curr_time = get_time();

	list_for_each_entry_safe(conn, next_conn, &connection_list, list) {
		// clean connections after timeout over
		if (curr_time - conn->last_updated >= 25) {
			delete_connection(conn);
		}
		else if (mode == SERACH_BY_C_S) {
			// check client to server
			if (conn->client_ip == src_ip && conn->client_port == src_port &&
					conn->server_ip == dst_ip && conn->server_port == dst_port) {
				return (ConnectionAndSide) {conn, SIDE_CLIENT};
			}
			// check server to client
			else if (conn->client_ip == dst_ip && conn->client_port == dst_port &&
					conn->server_ip == src_ip && conn->server_port == src_port) {
				return (ConnectionAndSide) {conn, SIDE_SERVER};
			}
		}
		else if (mode == SEARCH_BY_PROXY) {
			// check proxy as client to server
			if (conn->proxy_as_client_port == src_port &&
					conn->server_ip == dst_ip && conn->server_port == dst_port) {
				return (ConnectionAndSide) {conn, SIDE_PROXY_CLIENT};
			}
			// check proxy as server to client
			else if (conn->proxy_as_server_port == src_port &&
					conn->client_ip == dst_ip && conn->client_port == dst_port) {
				return (ConnectionAndSide) {conn, SIDE_PROXY_SERVER};
			}
		}
	}

	// no connection found
	return (ConnectionAndSide) {NULL, SIDE_INVALID};
}


static void destroy_list(void) {
	ConnectionRow *conn, *next_conn;

	list_for_each_entry_safe(conn, next_conn, &connection_list, list) {
		if (conn != NULL) {
			delete_connection(conn);
		}
	}
}



static struct file_operations rules_fops = {
		.owner = THIS_MODULE,
};

static int conn_to_string(ConnectionRow* conn, char* string) {
	return sprintf(string, "%u %hu %u %hu %hu %hu %d %d %d\n",
			conn->client_ip, conn->client_port, conn->server_ip, conn->server_port,
			conn->proxy_as_server_port, conn->proxy_as_client_port,
			conn->regular_state, conn->proxy_to_client_state, conn->proxy_to_server_state);
}


ssize_t display_connections_table(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	int chars_read = 0;
	int total_chars_read = 0;
	ConnectionRow *conn, *next_conn;
	__kernel_time_t curr_time = get_time();
	// loop on all connections
	list_for_each_entry_safe(conn, next_conn, &connection_list, list) {
		// clean old connections
		if (curr_time - conn->last_updated >= 25) { // connection is old
			delete_connection(conn);
		}
		else {
			chars_read = conn_to_string(conn, buf);
			buf += chars_read;
			total_chars_read += chars_read; // assume we never pass PAGE_SIZE //TODO can we assume it?
		}
	}

	return total_chars_read;
}

ssize_t actions_on_connection(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	{ //sysfs store implementation
	ConnectionRow* conn;
	unsigned int action, client_ip, server_ip;
	__u16  client_port, server_port, proxy_as_client;
	int res = sscanf(buf, "%u %u %hu %u %hu %hu",
			&action, &client_ip, &client_port, &server_ip, &server_port, &proxy_as_client);
	if (res < 0) return -EINVAL;

	else if (action == ACTION_ADD_PROXY_AS_CLIENT) {
		// proxy sent C as src, S as dst, to find conn, which adding proxy_as_client
		if (res != 6) return -EINVAL;
		conn = get_connection(client_ip, client_port, server_ip, server_port, SERACH_BY_C_S).connection;
		if (conn == NULL) return -EINVAL;
		conn->proxy_as_client_port = proxy_as_client;
	}
	else {return -EINVAL;}

	return count;
}

ssize_t clear_connections(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	{

	destroy_list();
	return count;
}


static DEVICE_ATTR(show_and_handle_connections, S_IROTH | S_IWOTH , display_connections_table, actions_on_connection);

static DEVICE_ATTR(clear_connections, S_IWOTH , NULL, clear_connections);


int init_hw4_connections(struct class* sysfs_class_input) {
	// init sysfs device:

	//create char device
	major_number = register_chrdev(0, "fw_conn", &rules_fops);
	if (major_number < 0)
		return -1;

	//chnage sysfs class to given sysfs class
	sysfs_class = sysfs_class_input;

	//create sysfs devices
	sysfs_device = device_create(sysfs_class, NULL, MKDEV(major_number, 0), NULL, "fw_con_tab");
	if (IS_ERR(sysfs_device))
	{
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "fw_conn");
		return -1;
	}

	//create sysf file attribute - show and handle connection
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_show_and_handle_connections.attr))
	{
		device_destroy(sysfs_class, MKDEV(major_number, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "fw_conn");
		return -1;
	}

	// create sysfs file attirbute - clear connection table
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_clear_connections.attr))
	{
		device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_show_and_handle_connections.attr);
		device_destroy(sysfs_class, MKDEV(major_number, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "fw_conn");
		return -1;
	}

	return 0;
}


void exit_hw4_connections(void) {
	// delete connections table
	destroy_list();

	// unregister and remove sysfs
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_clear_connections.attr);
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_show_and_handle_connections.attr);
	device_destroy(sysfs_class, MKDEV(major_number, 0));
	// don't need to destroy sysfs class, because wasn't created here
	unregister_chrdev(major_number, "fw_conn");
}
