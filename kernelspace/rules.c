#include "rules.h"


MODULE_LICENSE("GPL");

static int major_number;
static struct class* sysfs_class = NULL;
static struct device* sysfs_device = NULL;
static rule_t rule_list[MAX_RULES];
static unsigned int rules_num = 0;
static unsigned int is_active = 0;


static rule_t localhost_rule = {"__localhost", DIRECTION_ANY,
		LOCALHOST, LOCALHOST_GATE, 8,
		LOCALHOST, LOCALHOST_GATE, 8,
		PROT_ANY, PORT_ANY, PORT_ANY, ACK_ANY, NF_ACCEPT
};


static struct file_operations rules_fops = {
		.owner = THIS_MODULE,
};

bool is_fw_active(void) {return is_active;}

bool is_packet_localhost(struct sk_buff* skb) {
	// localhost is direction any, so we don't need to check direction and can send NULL
	return isRuleValid(skb, &localhost_rule, NULL, NULL);
}


RuleResult basicChecksPacket(struct sk_buff* skb) {
	if (!is_active)
		return (RuleResult) {NF_ACCEPT, REASON_FW_INACTIVE};
	// assert packet is IPv4, if not, we just accept without checking rules
	if (!isIPv4(skb))
		return (RuleResult) {NF_ACCEPT, REASON_NOT_IPV4};
	// check for localhost packet
	if (is_packet_localhost(skb))
		return (RuleResult) {NF_ACCEPT, REASON_LOCALHOST};
	// check for xmax packet
	if (isXmaxPacket(skb))
		return (RuleResult) {NF_DROP, REASON_XMAS_PACKET};

	return (RuleResult) {ACTION_NOT_DECIDED, REASON_CONNECTION};
}

RuleResult checkPacketRules(struct sk_buff* skb, const struct net_device *in, const struct net_device *out) {

	int i;

	for (i = 0; i < rules_num; i++) {
		if (isRuleValid(skb, &rule_list[i], in, out)) {
			RuleResult rr = {rule_list[i].action, i};
			return rr;
		}
	}

	// no matching rule found
	return (RuleResult) {NF_ACCEPT, REASON_NO_MATCHING_RULE};
}

bool isIPv4(struct sk_buff* skb) {
	struct iphdr* ip_header = (struct iphdr*) skb_network_header(skb);
	return ip_header->version == IP_VERSION;
}

bool isProtTCPValid(struct iphdr* ip_header, rule_t* rule) {
	// check protocol valid
	if (rule->protocol != PROT_TCP && rule->protocol != PROT_ANY)
		return false;
	// get tcp header
	struct tcphdr* tcp_header = (struct tcphdr*)((char*)ip_header + (ip_header->ihl * 4));

	// check source port
	if (rule->src_port != PORT_ANY) {
		int src_port = ntohs(tcp_header->source);
		if (rule->src_port == PORT_ABOVE_1023) { // rule is: port>1023
			if (src_port <= 1023) return false;
		}
		else if (src_port != rule->src_port)
			return false;
	}
	// check dest port
	if (rule->dst_port != PORT_ANY) {
		int dst_port = ntohs(tcp_header->dest);
		if (rule->dst_port == PORT_ABOVE_1023) { // rule is: port>1023
			if (dst_port <= 1023) return false;
		}
		else if (dst_port != rule->dst_port)
			return false;
	}
	// check ack valid
	if (rule->ack != ACK_ANY && tcp_header->ack != rule->ack)
		return false;

	return true;
}

bool isProtUDPValid(struct iphdr* ip_header, rule_t* rule) {
	// check protocol valid
	if (rule->protocol != PROT_UDP && rule->protocol != PROT_ANY)
		return false;

	// get udp header
	struct udphdr* udp_header = (struct udphdr*)((char*)ip_header + (ip_header->ihl * 4));

	// check source port
	if (rule->src_port != PORT_ANY) {
		if (rule->src_port == PORT_ABOVE_1023 && udp_header->source <= 1023) // rule is: port>1023
			return false;
		else if (udp_header->source != rule->src_port)
			return false;
	}
	// check dest port
	if (rule->dst_port != PORT_ANY) {
		if (rule->dst_port == PORT_ABOVE_1023 && udp_header->dest <= 1023) // rule is: port>1023
			return false;
		else if (udp_header->dest != rule->dst_port)
			return false;
	}

	return true;
}

bool isRuleValid(struct sk_buff* skb, rule_t* rule,
		const struct net_device *in, const struct net_device *out)
{
	// check direction
	if (rule->direction == DIRECTION_IN) { // direction is from outside to inside
		if (in->name != NULL && !EQUALS(in->name, OUT_NET_DEVICE_NAME))
			return false;
		if (out->name != NULL && !EQUALS(out->name, IN_NET_DEVICE_NAME))
			return false;
		if (in->name == NULL && out->name == NULL)
			return false;
	}
	else if (rule->direction == DIRECTION_OUT) { // direction is from inside to outside
		if (in->name != NULL && !EQUALS(in->name, IN_NET_DEVICE_NAME))
			return false;
		if (out->name != NULL && !EQUALS(out->name, OUT_NET_DEVICE_NAME))
			return false;
		if (in->name == NULL && out->name == NULL)
			return false;
	}

	struct iphdr* ip_header = (struct iphdr*) skb_network_header(skb);
	// check ip address - compare network prefix
	if ((ip_header->saddr & rule->src_prefix_mask) !=
			(rule->src_ip & rule->src_prefix_mask)) {
		return false;
	}
	if ((ip_header->daddr & rule->dst_prefix_mask) !=
			(rule->dst_ip & rule->dst_prefix_mask)) {
		return false;
	}
	// check protocol
	switch(ip_header->protocol) {
	case PROT_TCP:
		if (!isProtTCPValid(ip_header, rule)) return false;
		break;

	case PROT_UDP:
		if (!isProtUDPValid(ip_header, rule)) return false;
		break;

	case PROT_ICMP:
		if (rule->protocol != PROT_ICMP && rule->protocol != PROT_ANY) {
			return false;
		}
		break;

	default:
		if (rule->protocol != PROT_OTHER && rule->protocol != PROT_ANY)
			return false;
		break;
	}

	return true;
}


bool isXmaxPacket(struct sk_buff *skb) {
	struct iphdr* ip_header = (struct iphdr*) skb_network_header(skb);
	if (ip_header->protocol == PROT_TCP) {
		struct tcphdr* tcp_header = (struct tcphdr*)((char*)ip_header + (ip_header->ihl * 4));
		if (tcp_header->psh && tcp_header->urg && tcp_header->fin)
			return true;
	}
	return false;
}


int rule_to_string(rule_t* rule, char* string) {
	return sprintf(string, "%20s %u "
			"%u %u %u " // src ip
			"%u %u %u " // dst ip
			"%u %u %u %u %u\n",
			rule->rule_name, rule->direction,
			rule->src_ip, rule->src_prefix_mask, rule->src_prefix_size,
			rule->dst_ip, rule->dst_prefix_mask, rule->dst_prefix_size,
			rule->protocol, rule->src_port, rule->dst_port, rule->ack, rule->action);
}


int string_to_rule(rule_t* rule, const char* string) {
	int chars_read = 0;
	sscanf(string, "%20s %u "
			"%u %u %hhu " // src ip
			"%u %u %hhu " // dst ip
			"%hhu %hu %hu %u %hhu"
			"%n",
			rule->rule_name, &rule->direction,
			&rule->src_ip, &rule->src_prefix_mask, &rule->src_prefix_size,
			&rule->dst_ip, &rule->dst_prefix_mask, &rule->dst_prefix_size,
			&rule->protocol, &rule->src_port, &rule->dst_port, &rule->ack, &rule->action,
			&chars_read);
	return chars_read;
}


ssize_t display_rules(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	int chars_read = 0;
	int total_chars_read = 0;
	unsigned int i = 0;
	for (; i < rules_num; i++) {
		chars_read = rule_to_string(&rule_list[i], buf);
		buf += chars_read;
		total_chars_read += chars_read; // assume we never pass PAGE_SIZE with max 50 rules
	}

	return total_chars_read;
}


ssize_t store_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
	rules_num = 0;
	int chars_read = 0;
	int i;
	for (i = 0; (chars_read = string_to_rule(&rule_list[i], buf)) > 0; ++i) {
		buf += chars_read;
		rules_num++;
		if (rules_num == MAX_RULES) {
			printk(KERN_INFO "stopped after trying to load more than 50 rules");
			break;
		}
	}
	return count;
}

ssize_t display_active(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	return scnprintf(buf, PAGE_SIZE, "%u\n", is_active);
}

ssize_t display_rules_size(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	return scnprintf(buf, PAGE_SIZE, "%u\n", rules_num);
}


ssize_t switch_active(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
	unsigned int temp;
	if (sscanf(buf, "%u", &temp) == 1) {
		if (temp == 0 || temp == 1) {
			is_active = temp;
		}
	}
	return count;
}

static DEVICE_ATTR(handle_rules, S_IRWOTH , display_rules, store_rules);
static DEVICE_ATTR(active, S_IRWOTH , display_active, switch_active);
static DEVICE_ATTR(rules_size, S_IROTH , display_rules_size, NULL); //TODO check



int init_hw4_rules(struct class* sysfs_class_input) {
	// init sysfs device:

	//create char device
	major_number = register_chrdev(0, "fw_rules", &rules_fops);
	if (major_number < 0)
		return -1;

	//chnage sysfs class to given sysfs class
	sysfs_class = sysfs_class_input;

	//create sysfs devices
	sysfs_device = device_create(sysfs_class, NULL, MKDEV(major_number, 0), NULL, "fw_rules");
	if (IS_ERR(sysfs_device))
	{
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "fw_rules");
		return -1;
	}

	//create sysf file attribute - handle_rules
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_handle_rules.attr))
	{
		device_destroy(sysfs_class, MKDEV(major_number, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "fw_rules");
		return -1;
	}

	//create sysfs file attribute - active
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_active.attr))
	{
		device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_handle_rules.attr);
		device_destroy(sysfs_class, MKDEV(major_number, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "fw_rules");
		return -1;
	}

	//create sysfs file attribute - rules_size
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_rules_size.attr))
	{
		device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_handle_rules.attr);
		device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_active.attr);
		device_destroy(sysfs_class, MKDEV(major_number, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "fw_rules");
		return -1;
	}


	return 0;
}


void exit_hw4_rules(void) {
	// unregister and remove sysfs
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_rules_size.attr);
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_active.attr);
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_handle_rules.attr);
	device_destroy(sysfs_class, MKDEV(major_number, 0));
	// don't need to destroy sysfs class, because wasn't created here
	unregister_chrdev(major_number, "fw_rules");
}
