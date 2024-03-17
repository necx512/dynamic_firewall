#ifndef DNS_HANDLE_QDGLENJDGPQSD_H
#define DNS_HANDLE_QDGLENJDGPQSD_H
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
	int nb_replies;
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

struct dns_replies *export_dns_replies(struct dnshdr *dnshdr, struct dns_queries *queries);
struct dns_queries *export_dns_queries(struct dnshdr *dnshdr);
void free_dns_queries(struct dns_queries **queries_top);
void free_dns_replies(struct dns_replies **replies_top);
#endif
