/*
 * IPv6 Packet Counter - Basic Level
 * Counts all IPv6 packets using Netfilter hooks
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ipv6.h>
#include <linux/skbuff.h>
#include <linux/atomic.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Student");
MODULE_DESCRIPTION("IPv6 Packet Counter - Basic Level");
MODULE_VERSION("1.0");

// Global counter for IPv6 packets
static atomic_t ipv6_packet_count = ATOMIC_INIT(0);

// Netfilter hook structure
static struct nf_hook_ops nfho;

// Hook function to intercept packets
static unsigned int hook_func(void *priv, struct sk_buff *skb,
                             const struct nf_hook_state *state)
{
    struct ipv6hdr *ipv6_header;
    
    // Check if this is an IPv6 packet
    if (!skb)
        return NF_ACCEPT;
    
    // Get IPv6 header
    ipv6_header = ipv6_hdr(skb);
    if (!ipv6_header)
        return NF_ACCEPT;
    
    // Increment counter for IPv6 packets
    atomic_inc(&ipv6_packet_count);
    
    // Log every 10th packet to avoid flooding
    if (atomic_read(&ipv6_packet_count) % 10 == 0) {
        printk(KERN_INFO "IPv6_Counter_Basic: Total IPv6 packets: %d\n", 
               atomic_read(&ipv6_packet_count));
    }
    
    return NF_ACCEPT;
}

// Module initialization
static int __init ipv6_counter_init(void)
{
    printk(KERN_INFO "IPv6_Counter_Basic: Module loading...\n");
    
    // Initialize hook structure
    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET6;  // IPv6 protocol family
    nfho.priority = NF_IP6_PRI_FIRST;
    
    // Register the hook
    if (nf_register_net_hook(&init_net, &nfho) < 0) {
        printk(KERN_ERR "IPv6_Counter_Basic: Failed to register netfilter hook\n");
        return -1;
    }
    
    printk(KERN_INFO "IPv6_Counter_Basic: Module loaded successfully\n");
    printk(KERN_INFO "IPv6_Counter_Basic: Ready to count IPv6 packets\n");
    
    return 0;
}

// Module cleanup
static void __exit ipv6_counter_exit(void)
{
    // Unregister the hook
    nf_unregister_net_hook(&init_net, &nfho);
    
    printk(KERN_INFO "IPv6_Counter_Basic: Final count: %d IPv6 packets\n", 
           atomic_read(&ipv6_packet_count));
    printk(KERN_INFO "IPv6_Counter_Basic: Module unloaded\n");
}

module_init(ipv6_counter_init);
module_exit(ipv6_counter_exit);
