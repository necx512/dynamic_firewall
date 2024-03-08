/*****************************************************
 * This code was compiled and tested on Ubuntu 18.04.1
 * with kernel version 4.15.0
 *****************************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

static struct nf_hook_ops *nfho = NULL;


struct dnshdr {
	__be16 id;
	__be16 flags;
	__be16 questions;
	__be16 answer_rrs;
	__be16 auth_rrs;
	__be16 add_rrs;
} __attribute__((packed));

static void print_dns_req(struct sk_buff *skb)
{
	struct udphdr *udph;
	struct dnshdr *dnsh;
	unsigned char *current_ptr;

	udph = udp_hdr(skb);
	dnsh = (struct dnshdr *)(udph+1);
	current_ptr = (unsigned char *)(dnsh+1);
	int size;
	while(1){
		size = (int)*current_ptr;
		current_ptr++;
		if(size == 0){
			break;
		} else {
			for(int i=0;i<size;++i){
				printk(KERN_CONT "%c",current_ptr[i]);
			}
			current_ptr += size;
		}
		printk(KERN_CONT ".");	
	}
	printk("\n");
}

static unsigned int hfunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph = NULL;
	struct udphdr *udph = NULL;
	struct tcphdr *tcph = NULL;

	//struct dnshdr *dnsh = NULL;
	if (!skb)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		if(udph->dest == 0x3500){ // port 53 big endian
			print_dns_req(skb);

		}
	}
	else if (iph->protocol == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
	}
	
		return NF_ACCEPT;
	return NF_DROP;
}

static int __init LKM_init(void)
{
	nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	
	/* Initialize netfilter hook */
	nfho->hook 	= (nf_hookfn*)hfunc;		/* hook function */
	nfho->hooknum 	= NF_INET_POST_ROUTING;		/* received packets */
	nfho->pf 	= PF_INET;			/* IPv4 */
	nfho->priority 	= NF_IP_PRI_FIRST;		/* max hook priority */
	
	nf_register_net_hook(&init_net, nfho);
	return 0;
}

static void __exit LKM_exit(void)
{
	nf_unregister_net_hook(&init_net, nfho);
	kfree(nfho);
}

module_init(LKM_init);
module_exit(LKM_exit);
MODULE_LICENSE("GPL");
