#ifndef LOGS_H_
#define LOGS_H_

#include "fw.h"
#include "utils.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/time.h>
#include <linux/limits.h>

#define MAX_LOGS 1000
#define MAX_LOG_LENGTH 150
#define LOG_DONT_EXIST -1

/**
 * copy given log to given string
 * @ret - nums of chars copied
 */
int log_to_string(log_row_t* log, char* string);

/** prepare char device to print when opened */
int open_log(struct inode *_inode, struct file *_file);

/** read all logs to buff*/
ssize_t read_log(struct file *filp, char *buff, size_t length, loff_t *offp);

/** transform given skb and rule_result to given log */
void skb_to_log(struct sk_buff* skb, unsigned char hooknum, RuleResult rule_result, log_row_t* log);

/** @ret logs equals except time & count */
bool are_logs_equals(log_row_t* log1, log_row_t* log2);

/** @ret - index of log in log_list. if log don't exist, @ret -1 */
int log_index_in_list(struct sk_buff* skb, unsigned char hooknum, RuleResult rule_result);

/** @ret index in log_list of oldest log */
int get_oldest_log(void);

bool log_list_full(void);

bool log_list_empty(void);


/** add given log log_list
 *  if log already exist, then only update time and count
 *  if log_list is full, put new log instead of the oldest
 */
void add_log(struct sk_buff* skb, unsigned char hooknum, RuleResult rule_result);

/** print logs num to buf in user */
ssize_t display_size(struct device *dev, struct device_attribute *attr, char *buf);

/** clear log_list */
ssize_t clear(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

/**
 * initialize char device for log and sysfs attrubutes
 * @ret sysfs_class for success, and NULL for failure
 */
int init_hw4_logs(struct class* sysfs_class_input);

/** delete unregister and remove sysfs and char device */
void exit_hw4_logs(void);


#endif /* LOGS_H_ */
