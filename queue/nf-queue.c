
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>

#include <linux/types.h>
#include <linux/netfilter/nfnetlink_queue.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

/* only for NFQA_CT, not needed otherwise: */
#include <linux/netfilter/nfnetlink_conntrack.h>

#include <assert.h>
static struct mnl_socket *nl;

struct dns_queries
{
	struct dns_query_entry *entries;	
	int nb_queries;
	unsigned long length;
};
struct dns_query_entry
{
	char *name;
	unsigned short type;
	unsigned short class;

};

struct dns_replies
{
	struct dns_reply_entry *entries;	
	int nb_reply;
};
struct  __attribute__((__packed__)) dns_reply_entry
{
	unsigned short name;
	unsigned short type;
	unsigned short class;
	unsigned int ttl;
	unsigned short length;
	unsigned char *data;
};




struct dnshdr { // https://packetstormsecurity.com/files/36299/dnssmurf.c.html
  unsigned short int id;
  unsigned char  rd:1;           /* recursion desired */
  unsigned char  tc:1;           /* truncated message */
  unsigned char  aa:1;           /* authoritive answer */
  unsigned char  opcode:4;       /* purpose of message */
  unsigned char  qr:1;           /* response flag */
  unsigned char  rcode:4;        /* response code */
  unsigned char  unused:2;       /* unused bits */
  unsigned char  pr:1;           /* primary server required (non standard) */
  unsigned char  ra:1;           /* recursion available */
  unsigned short int que_num;
  unsigned short int rep_num;
  unsigned short int num_rr;
  unsigned short int num_rrsup;
};

static struct dns_replies *export_dns_replies(struct dnshdr *dnshdr, struct dns_queries *queries){
	unsigned char *ptr_reply = (unsigned char *) (dnshdr + 1);
	ptr_reply += queries->length;

	struct dns_replies *replies = malloc(sizeof(*replies));
	replies->nb_reply = ntohs(dnshdr->rep_num);
	replies->entries = malloc( (replies->nb_reply) * sizeof(struct dns_reply_entry));


	for(int reply_idx = 0 ; reply_idx < replies->nb_reply ; ++reply_idx){

		replies->entries[reply_idx].name = *(unsigned short *)(&ptr_reply[0]);
		replies->entries[reply_idx].type = *(unsigned short *)(&ptr_reply[2]);
		replies->entries[reply_idx].class = *(unsigned short *)(&ptr_reply[4]);
		replies->entries[reply_idx].ttl = *(unsigned int *)(&ptr_reply[6]);
		replies->entries[reply_idx].length = *(unsigned short *)(&ptr_reply[10]);
		replies->entries[reply_idx].data = malloc(replies->entries[reply_idx].length);
		memcpy(replies->entries[reply_idx].data, &ptr_reply[12], replies->entries[reply_idx].length);



		ptr_reply += (12/*length of header for one reply*/ + replies->entries[reply_idx].length);
	}
	return replies;
}

static struct dns_queries *export_dns_queries(struct dnshdr *dnshdr){
	struct dns_queries *queries = malloc(sizeof(*queries));
	queries->nb_queries = ntohs(dnshdr->que_num);
	queries->entries = malloc( (queries->nb_queries) * sizeof(struct dns_query_entry));


	unsigned char *ptr = (unsigned char *)(dnshdr+1);


	assert(queries->nb_queries == 1); //on a pas testé sur plus donc pour le moment on reste sur 1
	for(int query_idx = 0 ; query_idx < queries->nb_queries ; ++query_idx){

		// get the size of the domain name
		int len_str=0;
		while(*ptr != 0){
			ptr++;
			len_str++;
		}
		ptr = ptr - len_str;

		// Allocate place for storing the domain name
		queries->entries[query_idx].name = calloc(len_str,1);

		// copy the domain name
		int name_idx=0;
		while(*ptr != 0){
			int size=*ptr;
			for(int i=0;i<size;++i){
				queries->entries[query_idx].name[name_idx++] = ptr[1+i];//off by one because of length
			}
			queries->entries[query_idx].name[name_idx++] = '.';//off by one because of length
			ptr = ptr + size + 1;
		}
		queries->entries[query_idx].name[name_idx-1] = '\0';
		ptr++;

		// copy the type
		queries->entries[query_idx].type = *(unsigned short *)ptr;
		ptr+=2;

		queries->entries[query_idx].class = *(unsigned short *)ptr;
		ptr+=2;
	}

	queries->length = (unsigned long)ptr - (unsigned long)dnshdr - sizeof(*dnshdr);

	return queries;
}

void free_dns_queries(struct dns_queries *queries){
	for(int query_idx = 0 ; query_idx < queries->nb_queries ; ++query_idx){
		free(queries->entries[query_idx].name);
	}
	free(queries);
}

static void
nfq_send_verdict(int queue_num, uint32_t id)
{
        char buf[MNL_SOCKET_BUFFER_SIZE];
        struct nlmsghdr *nlh;
        struct nlattr *nest;

        nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, queue_num);
        nfq_nlmsg_verdict_put(nlh, id, NF_ACCEPT);

        /* example to set the connmark. First, start NFQA_CT section: */
        nest = mnl_attr_nest_start(nlh, NFQA_CT);

        /* then, add the connmark attribute: */
        mnl_attr_put_u32(nlh, CTA_MARK, htonl(42));
        /* more conntrack attributes, e.g. CTA_LABELS could be set here */

        /* end conntrack section */
        mnl_attr_nest_end(nlh, nest);

        if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
                perror("mnl_socket_send");
                exit(EXIT_FAILURE);
        }
}
static int queue_cb(const struct nlmsghdr *nlh, void *data)
{
	static int idxnbr = 0;
        struct nfqnl_msg_packet_hdr *ph = NULL;
        struct nlattr *attr[NFQA_MAX+1] = {};
        uint32_t id = 0, skbinfo;
        struct nfgenmsg *nfg;
        uint16_t plen;

        if (nfq_nlmsg_parse(nlh, attr) < 0) {
                perror("problems parsing");
                return MNL_CB_ERROR;
        }

        nfg = mnl_nlmsg_get_payload(nlh);

        if (attr[NFQA_PACKET_HDR] == NULL) {
                fputs("metaheader not set\n", stderr);
                return MNL_CB_ERROR;
        }

        ph = mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);

        plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
        void *payload = mnl_attr_get_payload(attr[NFQA_PAYLOAD]);
	struct iphdr *iph = (struct iphdr *) payload;
	

        skbinfo = attr[NFQA_SKB_INFO] ? ntohl(mnl_attr_get_u32(attr[NFQA_SKB_INFO])) : 0;

        if (attr[NFQA_CAP_LEN]) {
                uint32_t orig_len = ntohl(mnl_attr_get_u32(attr[NFQA_CAP_LEN]));
                if (orig_len != plen)
                        printf("truncated ");
        }

        if (skbinfo & NFQA_SKB_GSO)
                printf("GSO ");

        id = ntohl(ph->packet_id);

	//iph->daddr
	//iph->saddr
	//https://github.com/jvehent/nfqueue_recorder/blob/master/nfqueue_recorder.c

	struct udphdr *udphdr = (struct udphdr *)(iph+1);
	int found = 0;
	if(iph->protocol == 0x11 && udphdr->source == 0x3500) //DNS on UDP
	{
		struct dnshdr *dnshdr = (struct dnshdr *)(udphdr+1);
		struct dns_queries *queries = export_dns_queries(dnshdr);
		struct dns_replies *replies = export_dns_replies(dnshdr, queries);
		

		for(int i=0; i < replies->nb_reply ; ++i){
			if(ntohs(replies->entries[i].type) == 1) // type A
			{
				found=1;
				int ip = *(unsigned int *)(replies->entries[i].data);
				int ip_a = (ip>>0) & 0xff;
				int ip_b = (ip>>8) & 0xff;
				int ip_c = (ip>>16) & 0xff;
				int ip_d = (ip>>24) & 0xff;
				printf("%d : %s : %d.%d.%d.%d\n",++idxnbr, queries->entries[0].name,ip_a, ip_b, ip_c, ip_d);
			}
		}

		free_dns_queries(queries);
	}
	if(found == 1)
		printf("\n");
				  

/*	printf("IP DST = %x\n",iph->daddr);
        printf("packet received (id=%u hw=0x%04x hook=%u, payload len %u",
                id, ntohs(ph->hw_protocol), ph->hook, plen);*/

        /*
         * ip/tcp checksums are not yet valid, e.g. due to GRO/GSO.
         * The application should behave as if the checksums are correct.
         *
         * If these packets are later forwarded/sent out, the checksums will
         * be corrected by kernel/hardware.
         */
/*        if (skbinfo & NFQA_SKB_CSUMNOTREADY)
                printf(", checksum not ready");
        puts(")");*/

        nfq_send_verdict(ntohs(nfg->res_id), id);

        return MNL_CB_OK;
}

int main(int argc, char *argv[])
{
	assert(sizeof(struct dnshdr) == 12);
	printf("sizeof dnshdr OK\n");
	// assert(sizeof(struct dns_reply_entry) == 12);
	// printf("sizeof dns_reply_entry OK\n");
        char *buf;
        /* largest possible packet payload, plus netlink data overhead: */
        size_t sizeof_buf = 0xffff + (MNL_SOCKET_BUFFER_SIZE/2);
        struct nlmsghdr *nlh;
        int ret;
        unsigned int portid, queue_num;

        if (argc != 2) {
                printf("Usage: %s [queue_num]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
        queue_num = atoi(argv[1]);

        nl = mnl_socket_open(NETLINK_NETFILTER);
        if (nl == NULL) {
                perror("mnl_socket_open");
                exit(EXIT_FAILURE);
        }

        if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
                perror("mnl_socket_bind");
                exit(EXIT_FAILURE);
        }
        portid = mnl_socket_get_portid(nl);

        buf = malloc(sizeof_buf);
        if (!buf) {
                perror("allocate receive buffer");
                exit(EXIT_FAILURE);
        }

        nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
        nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);

        if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
                perror("mnl_socket_send");
                exit(EXIT_FAILURE);
        }

        nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
        nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

        mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
        mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

        if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
                perror("mnl_socket_send");
                exit(EXIT_FAILURE);
        }

        /* ENOBUFS is signalled to userspace when packets were lost
         * on kernel side.  In most cases, userspace isn't interested
         * in this information, so turn it off.
         */
        ret = 1;
        mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &ret, sizeof(int));

        for (;;) {
                ret = mnl_socket_recvfrom(nl, buf, sizeof_buf);
                if (ret == -1) {
                        perror("mnl_socket_recvfrom");
                        exit(EXIT_FAILURE);
                }

                ret = mnl_cb_run(buf, ret, 0, portid, queue_cb, NULL);
                if (ret < 0){
                        perror("mnl_cb_run");
                        exit(EXIT_FAILURE);
                }
        }

        mnl_socket_close(nl);

        return 0;
}
