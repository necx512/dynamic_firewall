#ifndef _CACHE_UGTBHNDHK_H
#define _CACHE_UGTBHNDHK_H

struct link_list
{
	struct link_list *parent;
	int child_idx;

	struct link_list **childs;
	int nb_valid_childs;
	int nb_childs;


	uint32_t *list_ip;
	uint32_t nb_ip;//TODO : definir un max
	char *dns_name_part;
	time_t timestamp; 
	uint32_t ttl;
};

struct link_list *add_entry(char *dns_name);
void add_ip(struct link_list *in, uint32_t ip);
int is_ip_allowed(uint32_t ip, struct link_list *current);
void set_log_file(FILE *file);
void init_root(void);
void free_root(void);
void free_splitted_dns(char **parts, int nb_parts);
void print_tree(struct link_list *origin);
#endif
