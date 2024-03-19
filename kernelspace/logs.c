#include "logs.h"

MODULE_LICENSE("GPL");

static int major_number;
static struct class* sysfs_class = NULL;
static struct device* sysfs_device = NULL;
static log_row_t log_list[MAX_LOGS];
static unsigned int log_num = 0;
static char log_strings[MAX_LOGS*MAX_LOG_LENGTH];
static char* buffer_index;
static unsigned int buffer_len;

static struct file_operations fops = {
		.owner = THIS_MODULE,
		.open = open_log,
		.read = read_log
};


int log_to_string(log_row_t* log, char* string) {
	return sprintf(string, "%lu "
			"%u %u %u %u "
			"%u %u %u "
			"%d %u\n",
			log->timestamp,
			log->src_ip, log->dst_ip, log->src_port, log->dst_port,
			log->protocol, log->hooknum, log->action,
			log->reason, log->count);
}



int open_log(struct inode *_inode, struct file *_file) {
	// clear log_string
	buffer_len = 0;
	unsigned int i;
	for (i = 0; i < (unsigned) MAX_LOGS*MAX_LOG_LENGTH; i++) {
		log_strings[i] = '\0';
	}
	// copy log to buffer
	char* buf = log_strings;
	for (i = 0; i < log_num; i++) {
		int chars_printed_num = log_to_string(&log_list[i], buf);
		buf += chars_printed_num;
		buffer_len += chars_printed_num;
	}
	// initialize buffer position
	buffer_index = log_strings;

	return 0;
}


ssize_t read_log(struct file *filp, char *buff, size_t length, loff_t *offp) {
	ssize_t num_of_bytes;
	num_of_bytes = (buffer_len < length) ? buffer_len : length;

	if (num_of_bytes == 0) { // We check to see if there's anything to write to the user
		return 0;
	}

	if (copy_to_user(buff, buffer_index, num_of_bytes)) { // Send the data to the user through 'copy_to_user'
		return -EFAULT;
	} else { // fuction succeed, we just sent the user 'num_of_bytes' bytes, so we updating the counter and the string pointer index
		buffer_len -= num_of_bytes;
		buffer_index += num_of_bytes;
		return num_of_bytes;
	}
	return -EFAULT; // Should never reach here
}


void skb_to_log(struct sk_buff* skb, unsigned char hooknum, RuleResult rule_result, log_row_t* log) {
	log->timestamp = get_time(); // curr time
	log->hooknum = hooknum;
	log->action = rule_result.action;
	log->reason = rule_result.reason;
	struct iphdr* ip_header = (struct iphdr*) skb_network_header(skb);
	log->protocol = ip_header->protocol;
	log->src_ip = ip_header->saddr;
	log->dst_ip = ip_header->daddr;
	if (log->protocol == PROT_TCP) {
		struct tcphdr* tcp_header = (struct tcphdr*)((char*)ip_header + (ip_header->ihl * 4));
		log->src_port = ntohs(tcp_header->source);
		log->dst_port = ntohs(tcp_header->dest);
	}
	else if (log->protocol == PROT_UDP) {
		struct udphdr* udp_header = (struct udphdr*)((char*)ip_header + (ip_header->ihl * 4));
		log->src_port = ntohs(udp_header->source);
		log->dst_port = ntohs(udp_header->dest);
	}
	log->count = 1; // just this log for now
}

bool are_logs_equals(log_row_t* log1, log_row_t* log2) {
	if (log1->src_ip   != log2->src_ip) 	return false;
	if (log1->dst_ip   != log2->dst_ip) 	return false;
	if (log1->protocol != log2->protocol) 	return false;
	if (log1->hooknum  != log2->hooknum) 	return false;
	if (log1->action   != log2->action) 	return false;
	if (log1->reason   != log2->reason) 	return false;
	if (log1->protocol == PROT_TCP || log1->protocol == PROT_UDP) {
		// check for port only when protocol include ports
		if (log1->src_port != log2->src_port) 	return false;
		if (log1->dst_port != log2->dst_port) 	return false;
	}
	return true;
}

int log_index_in_list(struct sk_buff* skb, unsigned char hooknum, RuleResult rule_result) {

	log_row_t skb_log;
	skb_to_log(skb, hooknum, rule_result, &skb_log); // now we have the skb in log form
	// loop on all logs
	unsigned int i;
	for (i = 0; i < log_num; i++) {
		if (are_logs_equals(&skb_log, &log_list[i]))
			return i;
	}
	return LOG_DONT_EXIST;
}

int get_oldest_log(void) {
	int min_index = -1;
	unsigned long min_time = ULONG_MAX; // max size for unsigned long
	int i = 0;
	for (; i < log_num; i++) {
		if (min_time > log_list[i].timestamp) {
			min_time = log_list[i].timestamp;
			min_index = i;
		}
	}
	return min_index;
}

bool log_list_full(void) {return log_num == MAX_LOGS;}

bool log_list_empty(void) {return log_num == 0;}

void add_log(struct sk_buff* skb, unsigned char hooknum, RuleResult rule_result) {
	int log_index = log_index_in_list(skb, hooknum, rule_result);
	if (log_index == LOG_DONT_EXIST) { // need to add new log
		if (!log_list_full()) { // simply add this new log to list
			log_row_t* new_log = &log_list[log_num];
			skb_to_log(skb, hooknum, rule_result, new_log);
			log_num++;
		}
		else { // list full, so replace oldest log with this log
			int log_index = get_oldest_log();
			log_row_t* log_to_replace = &log_list[log_index];
			skb_to_log(skb, hooknum, rule_result, log_to_replace);
		}
	}
	else { // update log time and count
		log_row_t* log = &log_list[log_index];
		log->timestamp = get_time();
		log->count++;
	}
}

ssize_t display_size(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	return scnprintf(buf, PAGE_SIZE, "%u\n", log_num);
}

ssize_t clear(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
	char temp;
	if (sscanf(buf, "%c", &temp) == 1) {
		log_num = 0;
	}
	return count;
}


static DEVICE_ATTR(log_size, S_IROTH , display_size, NULL);
static DEVICE_ATTR(log_clear, S_IWOTH , NULL, clear);



int init_hw4_logs(struct class* sysfs_class_input)
{
	// init sysfs device:

	//create char device
	major_number = register_chrdev(0, "fw_log", &fops);
	if (major_number < 0)
		return -1;

	//chnage sysfs class to given sysfs class
	sysfs_class = sysfs_class_input;

	//create sysfs devices
	sysfs_device = device_create(sysfs_class, NULL, MKDEV(major_number, 0), NULL, "fw_log");
	if (IS_ERR(sysfs_device))
	{
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "fw_log");
		return -1;
	}

	//create sysfs file attribute - active
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_log_size.attr))
	{
		device_destroy(sysfs_class, MKDEV(major_number, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "fw_log");
		return -1;
	}

	//create sysfs file attribute - rules_size
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_log_clear.attr))
	{
		device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_log_size.attr);
		device_destroy(sysfs_class, MKDEV(major_number, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "fw_log");
		return -1;
	}

	return 0;
}

void exit_hw4_logs(void)
{
	// unregister and remove sysfs
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_log_clear.attr);
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_log_size.attr);
	device_destroy(sysfs_class, MKDEV(major_number, 0));
	unregister_chrdev(major_number, "fw_log");
}
