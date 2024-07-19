
#include <linux/module.h>       // included for all kernel modules
#include <linux/moduleparam.h>  // module parameter macros and hooks
#include <linux/kernel.h>       // included for KERN_DEBUG
#include <linux/init.h>         // included for __init and __exit macros
#include <linux/vmalloc.h>

//#undef __KERNEL__
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
//#define __KERNEL__

#include "tx.c"
#include "rx.c"
#include "mem/kreg.c"
#include "net/pdm.c"
#include "net/dump.c"
#include "net/struct.c"
#include "net/application_layer.c"
#include "time/timedelta.c"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arnav Das");
MODULE_DESCRIPTION("IPv6 Performance and Diagnostic Metrics (PDM) Destination Option");

static int debug = 0;
module_param(debug, int, S_IWUSR|S_IRUSR);

static struct nf_hook_ops tx_hook_ops = {
	.hook     = handle_tx_pkt,
	.pf       = PF_INET6,
	.hooknum  = NF_INET_LOCAL_OUT,
	.priority = NF_IP6_PRI_FILTER,
};
static struct nf_hook_ops rx_hook_ops = {
	.hook     = handle_rx_pkt,
	.pf       = PF_INET6,
	.hooknum  = NF_INET_LOCAL_IN,
	.priority = NF_IP6_PRI_FILTER,
};

static int __init ipv6_pdm_init(void) {
    pr_info(KERN_DEBUG "Starting PDM listener...\n");

    kreg_init();

    // Register Receiving and Transmission hooks
    nf_register_net_hook(&init_net, &tx_hook_ops);
    nf_register_net_hook(&init_net, &rx_hook_ops);
    return 0;    // Non-zero return means that the module couldn't be loaded.
}
static void __exit ipv6_pdm_cleanup(void) {

    kreg_destroy();

    nf_unregister_net_hook(&init_net, &tx_hook_ops);
    nf_unregister_net_hook(&init_net, &rx_hook_ops);

    pr_info(KERN_DEBUG "Cleaning up module.\n");
}

module_init(ipv6_pdm_init);
module_exit(ipv6_pdm_cleanup);
