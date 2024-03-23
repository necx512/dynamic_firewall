#ifndef _CACHE_UGTBHNDHK_H
#define _CACHE_UGTBHNDHK_H

struct link_list
{
	struct link_list *parent;

	struct link_list *childs;
	int nb_valid_childs;
	int nb_childs;


	uint32_t *list_ip;
	uint32_t nb_ip;//TODO : definir un max
	unsigned char *dns_name_part;
	time_t timestamp; 
	uint32_t ttl;
};

struct entry *add_entry(unsigned char *dns_name);
void add_ip(struct entry *in, uint32_t ip);
void set_ttl(struct entry *in, uint32_t ttl);
int is_ip_allowed(uint32_t ip);
void set_log_file(FILE *file);
#endif
