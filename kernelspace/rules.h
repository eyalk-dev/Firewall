#ifndef RULES_H_
#define RULES_H_


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/skbuff.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <stdbool.h>
#include <linux/string.h>
#include "fw.h"

#define EQUALS(x,y) (strcmp(x,y) == 0)
#define EMPTY_CHARS_IN_SSCANF 15
#define S_IRWOTH S_IROTH | S_IWOTH


bool is_fw_active(void);

bool is_packet_localhost(struct sk_buff* skb);

/**
 * basic checks for packet:
 * 1. is firewall not active? - accept
 * 2. is packet not IPv4? - accept
 * 3. is packet localhost? - accept
 * 4. is packet xmas? - accept
 * @ret action for checks or undecided if unfulfill
 */
RuleResult basicChecksPacket(struct sk_buff* skb);

/**
 * check packet to rules in table.
 * @ret - reason and action for this packet
 */
RuleResult checkPacketRules(struct sk_buff* skb, const struct net_device *in, const struct net_device *out);

/** @ret if this packet in IPv4 form */
bool isIPv4(struct sk_buff* skb);

/** @ret if given packet in protocol TCP fulfill given rule */
bool isProtTCPValid(struct iphdr* ip_header, rule_t* rule);

/** @ret if given packet in protocol UDP fulfill given rule */
bool isProtUDPValid(struct iphdr* ip_header, rule_t* rule);

/** @ret if given packet fulfill given rule */
bool isRuleValid(struct sk_buff* skb, rule_t* rule,
		const struct net_device *in, const struct net_device *out);

/** @ret if given packet is xmax packet */
bool isXmaxPacket(struct sk_buff *skb);

/**
 * copy rule to given string
 * @ret num of char copied
 */
int rule_to_string(rule_t* rule, char* string);

/**
 * copy values in given string to given rule
 * @ret num of chars copied
 */
int string_to_rule(rule_t* rule, const char* string);

/**
 * copy all rules to buf in user space
 * @ret num of chars copied
 */
ssize_t display_rules(struct device *dev, struct device_attribute *attr, char *buf);

/** clear all rules, and copy rules in buf to our current rules*/
ssize_t store_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

/** @ret - 0 for not active and 1 for active */
ssize_t display_rules_size(struct device *dev, struct device_attribute *attr, char *buf);

/** set active if given 1, and set inactive if given 0 */
ssize_t switch_active(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

/**
 * create char device "fw_rules",
 * use given sysfs_class and create sysfs class and attributes for rules
 * @ret - 0 for success, -1 for failure
 */
int init_hw4_rules(struct class* sysfs_class_input);

void exit_hw4_rules(void);


#endif /* RULES_H_ */
