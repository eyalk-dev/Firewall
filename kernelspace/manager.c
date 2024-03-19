// netfilter code based on the first code in this article: https://www.linuxjournal.com/article/7184
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/fs.h>
#include "fw.h"
#include "rules.h"
#include "logs.h"
#include "statefull.h"

MODULE_LICENSE("GPL");
// macro to inialize and register hooks
#define INIT_AND_REGISTER_HOOKS(netfilter_ops) \
		netfilter_ops.hook = main_hook; \
		netfilter_ops.pf = PF_INET; \
		netfilter_ops.priority = NF_IP_PRI_FIRST; \
		nf_register_hook(&netfilter_ops);

static struct nf_hook_ops netfilter_ops_pre; /* NF_IP_PRE_ROUTING */
static struct nf_hook_ops netfilter_ops_out; /* NF_INET_LOCAL_OUT */

static struct class* sysfs_class = NULL;



/**
 *  Function prototype in <linux/netfilter>
 *  func hooks accept packet from/to FW and reject elsewhere
 */
unsigned int main_hook(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff*))
{

	// check if FW active, IPV4
	RuleResult basic_result = basicChecksPacket(skb);

	if (basic_result.action != ACTION_NOT_DECIDED) {
		if (basic_result.reason == REASON_XMAS_PACKET)
			add_log(skb, hooknum, basic_result);
		// else - don't need to log
		return basic_result.action;
	}

	else if (hooknum == NF_INET_PRE_ROUTING) {
		return checkPacketPre(skb, in, out);
	}

	else if (hooknum == NF_INET_LOCAL_OUT) {
		return checkPacketLocalOut(skb, in, out);
	}

	else {
		printk(KERN_ERR "unkown hook!\n");
		return NF_DROP;
	}
}


int init_module(void) {
	// create sysfs class
	sysfs_class = class_create(THIS_MODULE, "fw");
	if (IS_ERR(sysfs_class)) {return -1;}
	// init log
	if (init_hw4_logs(sysfs_class) < 0) { // failure to initialize logs
		class_destroy(sysfs_class);
		return -1;
	}

	// init rules
	if (init_hw4_rules(sysfs_class) < 0)  {// failure to initialize rules
		exit_hw4_logs();
		class_destroy(sysfs_class);
		return -1;
	}

	// init connections
	if (init_hw4_connections(sysfs_class) < 0 ) { // failure to initialize connections
		exit_hw4_rules();
		exit_hw4_logs();
		class_destroy(sysfs_class);
		return -1;
	}

	// init netfilter - initialize and register hooks ops

	// input for FW - PASS
	netfilter_ops_pre.hooknum = NF_INET_PRE_ROUTING;
	INIT_AND_REGISTER_HOOKS(netfilter_ops_pre)
	// output of FW - PASS
	netfilter_ops_out.hooknum = NF_INET_LOCAL_OUT;
	INIT_AND_REGISTER_HOOKS(netfilter_ops_out)

	printk(KERN_INFO "module initalized\n");

	return 0;
}

void cleanup_module(void) {
	printk(KERN_INFO "remove module\n");
	// unregister our hooks ops
	nf_unregister_hook(&netfilter_ops_pre); /*unregister NF_INET_PRE_ROUTING hook*/
	nf_unregister_hook(&netfilter_ops_out); /*unregister NF_INET_LOCAL_OUT hook*/


	// unregister devices for connections
	exit_hw4_connections();

	// unregister devices for rules
	exit_hw4_rules();
	// unregister devices and for logs
	exit_hw4_logs();
	// delete class
	class_destroy(sysfs_class);
}
