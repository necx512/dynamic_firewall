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

#define NETLINK_TEST 17
static struct nf_hook_ops *nfho = NULL;
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

static unsigned int hfunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph = NULL;
	struct udphdr *udph = NULL;
	struct tcphdr *tcph = NULL;
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
}


static void netlink_test_recv_msg(struct sk_buff *skb)
{
    struct sk_buff *skb_out;
    struct nlmsghdr *nlh;
    int msg_size;
    char *msg;
    int pid;
    int res;

    nlh = (struct nlmsghdr *)skb->data;
    pid = nlh->nlmsg_pid; /* pid of sending process */
    msg = (char *)nlmsg_data(nlh);
    msg_size = strlen(msg);

    printk(KERN_INFO "netlink_test: Received from pid %d: %s\n", pid, msg);

    // create reply
    skb_out = nlmsg_new(msg_size, 0);
    if (!skb_out) {
      printk(KERN_ERR "netlink_test: Failed to allocate new skb\n");
      return;
    }

    // put received message into reply
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
    strncpy(nlmsg_data(nlh), msg, msg_size);

    printk(KERN_INFO "netlink_test: Send %s\n", msg);

    res = nlmsg_unicast(nl_sock, skb_out, pid);
    if (res < 0)
      printk(KERN_INFO "netlink_test: Error while sending skb to user\n");
}


static int __init LKM_init(void)
{
	nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	
	/* Initialize netfilter hook */
	nfho->hook 	= (nf_hookfn*)hfunc;		/* hook function */
	nfho->hooknum 	= NF_INET_POST_ROUTING;		/* received packets */
	nfho->pf 	= PF_INET;			/* IPv4 */
	nfho->priority 	= NF_IP_PRI_FIRST;		/* max hook priority */
	
	//nf_register_net_hook(&init_net, nfho);



        
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
	nf_unregister_net_hook(&init_net, nfho);
	kfree(nfho);
}

module_init(LKM_init);
module_exit(LKM_exit);
MODULE_LICENSE("GPL");
