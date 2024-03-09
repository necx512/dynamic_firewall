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
#include <net/sock.h> 
#include <linux/netlink.h>
#include <linux/skbuff.h>

static struct nf_hook_ops *nfho_prerouting = NULL;
static struct nf_hook_ops *nfho_postrouting = NULL;
int current_pid = 0;


#define NETLINK_TEST 17
struct sock *nl_sock = NULL;


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


static void netlink_test_send_msg(int msg_size, unsigned char *msg){
	if(current_pid == 0){
		printk("NO PID ASSOCIATED\n");
		return;
	} else {
		printk("HAS PID ASSOCIATED\n");
		return;
	}
	struct sk_buff *skb_out;
    	struct nlmsghdr *nlh;
    	int res;
    	// create reply
    	skb_out = nlmsg_new(msg_size, 0);
    	if (!skb_out) {
    	  printk(KERN_ERR "netlink_test: Failed to allocate new skb\n");
    	  return;
    	}

    	// put received message into reply
    	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    	NETLINK_CB(skb_out).dst_group = 0;
    	strncpy(nlmsg_data(nlh), msg, msg_size);

    	printk(KERN_INFO "netlink_test: Send %s\n", msg);

    	res = nlmsg_unicast(nl_sock, skb_out, current_pid);
    	if (res < 0)
    	  printk(KERN_INFO "netlink_test: Error while sending skb to user\n");

}


static void netlink_test_recv_msg(struct sk_buff *skb)
{
    if(skb == NULL)
	    return;
    struct nlmsghdr *nlh;
    int msg_size;
    char *msg;

    nlh = (struct nlmsghdr *)skb->data;
    if(nlh == NULL)
	    return;
    current_pid = nlh->nlmsg_pid;
    msg = (char *)nlmsg_data(nlh);
    msg_size = strlen(msg);


    printk(KERN_INFO "netlink_test: Received from pid %d: %s\n", current_pid, msg);
} 

/***********************************************************************************************/
static unsigned int prerouting_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph = NULL;
	struct udphdr *udph = NULL;
	struct tcphdr *tcph = NULL;
	unsigned char *current_ptr = NULL;
	int length = 0;
	if (!skb)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		length = udph->len - sizeof(struct udphdr); 
		if(udph->dest == 0x3500){ // port 53 big endian
			current_ptr = (unsigned char *)(udph+1);
			netlink_test_send_msg(3, "ok\0");
			//send_to_userspace(skb, current_ptr, length);

		}
	}
	else if (iph->protocol == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
	}
	
		return NF_ACCEPT;
}
static unsigned int postrouting_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph = NULL;
	struct udphdr *udph = NULL;
	struct tcphdr *tcph = NULL;
	unsigned char *current_ptr = NULL;
	int length = 0;
	if (!skb)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		length = udph->len - sizeof(struct udphdr); 
		if(udph->dest == 0x3500){ // port 53 big endian
			current_ptr = (unsigned char *)(udph+1);
			//send_to_userspace(skb, current_ptr, length);
		}
	}
	else if (iph->protocol == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
	}
	
		return NF_ACCEPT;
}
/***********************************************************************************************/

static int __init LKM_init(void)
{
	/* Initialize netfilter hook for pre routing */
	nfho_prerouting			= (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	nfho_prerouting->hook		= (nf_hookfn*)prerouting_hook;	/* hook function */
	nfho_prerouting->hooknum 	= NF_INET_PRE_ROUTING;		/* received packets */
	nfho_prerouting->pf		= PF_INET;			/* IPv4 */
	nfho_prerouting->priority	= NF_IP_PRI_FIRST;		/* max hook priority */
	//nf_register_net_hook(&init_net, nfho_prerouting);
	
	/* Initialize netfilter hook for post routing */
	nfho_postrouting		= (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	nfho_postrouting->hook		= (nf_hookfn*)postrouting_hook;	/* hook function */
	nfho_postrouting->hooknum	= NF_INET_POST_ROUTING;		/* received packets */
	nfho_postrouting->pf		= PF_INET;			/* IPv4 */
	nfho_postrouting->priority	= NF_IP_PRI_FIRST;		/* max hook priority */
	//nf_register_net_hook(&init_net, nfho_postrouting);



        /* Initialize netlink */ 
  	struct netlink_kernel_cfg cfg = {
		.input = netlink_test_recv_msg,
	};

  	nl_sock = netlink_kernel_create(&init_net, NETLINK_TEST, &cfg);
  	if (!nl_sock) {
  	  printk(KERN_ALERT "netlink_test: Error creating socket.\n");
  	  return -10;
  	}


	return 0;
}

static void __exit LKM_exit(void)
{
	nf_unregister_net_hook(&init_net, nfho_prerouting);
	nf_unregister_net_hook(&init_net, nfho_postrouting);

	kfree(nfho_prerouting);
	kfree(nfho_postrouting);
}

module_init(LKM_init);
module_exit(LKM_exit);
MODULE_LICENSE("GPL");
