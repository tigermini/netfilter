#include<linux/kernel.h>
#include<linux/module.h>
#include<linux/netfilter.h>
#include<linux/socket.h>
#include<linux/netfilter_ipv4.h>

static int skb_num;

static struct nf_hook_ops nf_prerouting;

static unsigned int nf_prerouting_fn(void *priv,
                    struct sk_buff *skb,
                    const struct nf_hook_state *state)
{
    if (skb_num < 10) {
        printk("num%d: skb->len = %d\n", skb_num, skb->len);
        skb_num++;
    }

    return NF_ACCEPT;
}

static int hook_init(void)
{
    int ret;

    printk("hook init start\n");

    nf_prerouting.pf = PF_INET;
    nf_prerouting.hooknum = NF_INET_PRE_ROUTING;
    nf_prerouting.priority = NF_IP_PRI_FIRST;
    nf_prerouting.hook = nf_prerouting_fn;
    ret = nf_register_net_hook(&init_net, &nf_prerouting);
    if (ret < 0) {
        printk("register hook failed\n");
        goto hook_out;
    }

    return 0;

hook_out:
    return ret;
}

static void hook_exit(void)
{
    printk("hook exit start\n");

    nf_unregister_net_hook(&init_net, &nf_prerouting);
}


module_init(hook_init);
module_exit(hook_exit);
