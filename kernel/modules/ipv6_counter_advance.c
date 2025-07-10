#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Advanced IPv6 Packet Counter with /proc export");
MODULE_VERSION("1.0");

#define PROC_NAME "ipv6_counter"

static struct nf_hook_ops nfho;
static unsigned long ipv6_packet_count = 0;
static struct proc_dir_entry *proc_file;

// Netfilter hook function for IPv6
static unsigned int ipv6_count_hook(void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state)
{
    ipv6_packet_count++;
    return NF_ACCEPT;
}

// /proc read function using seq_file
static int proc_show(struct seq_file *m, void *v)
{
    seq_printf(m, "IPv6 Packet Count: %lu\n", ipv6_packet_count);
    return 0;
}

static int proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, proc_show, NULL);
}

// Use struct proc_ops (for newer kernels)
static const struct proc_ops proc_fops = {
    .proc_open = proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int __init ipv6_counter_init(void)
{
    // Register Netfilter hook
    nfho.hook = ipv6_count_hook;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET6;
    nfho.priority = NF_IP6_PRI_FIRST;

    nf_register_net_hook(&init_net, &nfho);

    // Create /proc entry
    proc_file = proc_create(PROC_NAME, 0, NULL, &proc_fops);
    if (!proc_file) {
        pr_err("Failed to create /proc/%s\n", PROC_NAME);
        nf_unregister_net_hook(&init_net, &nfho);
        return -ENOMEM;
    }

    pr_info("IPv6 counter module loaded.\n");
    return 0;
}

static void __exit ipv6_counter_exit(void)
{
    // Remove /proc entry
    proc_remove(proc_file);

    // Unregister Netfilter hook
    nf_unregister_net_hook(&init_net, &nfho);

    pr_info("IPv6 counter module unloaded.\n");
}

module_init(ipv6_counter_init);
module_exit(ipv6_counter_exit);

