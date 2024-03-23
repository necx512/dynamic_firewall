#define TRUE 1
#define FALSE 0

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "cache.h"

static struct link_list *root = NULL;
static FILE *log_file = NULL;

static init_root(void){
	root = calloc(1,sizeof(*root)); // This will never be freed except at the end of the program.

	root->parent = NULL;

	root->childs = NULL;
	root->nb_valid_childs = 0;
	root->nb_childs = 0;

	root->list_ip = NULL;
	root->nb_ip = 0;
	root->dns_name_part = NULL;
	root->timestamp = 0;
	root-ttl = 0;
}


static void convert_b32_to_str(char strret[256], uint32_t nbr){
	int nbr_a = (nbr>>0)&0xff;
	int nbr_b = (nbr>>8)&0xff;
	int nbr_c = (nbr>>16)&0xff;
	int nbr_d = (nbr>>24)&0xff;
	memset(strret,0,256);
	sprintf(strret,"%d.%d.%d.%d",nbr_a,nbr_b,nbr_c,nbr_d);
}


static char **split_dns(char *dns_name, int *nb_parts){
	int len_name = strlen(dns_name);
	char *tmp = calloc(len_name+1,sizeof(*tmp)); // Free at the end on the function
	char **parts = NULL;
	int len_part=0;

	*nb_parts = 0


	for(int i=0;i<len_name+1;++i){
		if(i == len_name || dns_name[i] == '.') {
			parts = realloc(*parts,(*nb_parts + 1)*sizeof(parts)); // to be freed -> free_splitted_dns()
			parts[*nb_parts] = calloc(len_part+1, sizeof(*parts[*nb_parts])); // to be freed -> free_splitted_dns
			strncpy(parts[*nb_parts], tmp, len_part);

			//control
			for(int j=0;j<len_part;++j){
				assert(parts[*nb_parts][j] == tmp[j]);
			}
			assert(parts[*nb_parts][len_part] == '\0');

			*nb_parts = (*nb_parts)+1;
			len_part = 0;
		} else {
			tmp[len_part] = dns_name[i];
			len_part++;
		}
	}

	free(tmp);
	return parts;

}
void free_splitted_dns(char **parts, int nb_parts){
	for(int i=0;i<nb_parts;++i){
		free(parts[i]);
		parts[i] = NULL;
	}
	free(parts);
}
// OK
static int find_child_by_dns_part(struct link_list *parent, char *dns_part){
	if(parent == NULL)
	{
		if(root == NULL){
			init_root();
		}
		parent = root;
	}
	for(i=0; i < parent->nb_valid_childs ; ++i){
		if(strcmp(dns_part,parent->childs[i].dns_name_part) == 0){
			break;
		}
	}
	return i;// if i == parent->nb_valid_childs => not found
}

static int find_child_by_ref(struct link_list *child){
	struct link_list *parent = child->parent;
	for(i=0; i < parent->nb_valid_childs ; ++i){
		if(&parent->childs[i] == child){
			break;
		}
	}
	return i;// if i == parent->nb_valid_childs => not found
}

static int find_in_cache(char **splitted_dns_name, int nb_parts, struct link_list **founds/* should be allocated*/, int only_last_found){
	struct link_list *parent = NULL;
	int i;
	for(i=nb_parts-1; i>=0;--i){
		int idx = find_child_by_dns_part(parent, splitted_dns_name[i]);
		if(idx < parent->nb_valid_childs){
			if(only_last_found == 1)
				*founds = &parent->childs[i]
			else
				founds[nb_parts - i - 1] = &parent->childs[i];
			parent = &parent->childs[i];
		} else {
			break;
		}
	}
	return nb_parts - i - 1; // If we find all, then i==-1. Thus, we return nb_part-i-1 = nb_part - (-1)-1 = nb_part + 1 - 1 = nbpart
				 // If we dont find it, i=nb_part-1. Thus we return nb_part-i-1 = nb_part-(nb_part-1)-1=nb_part-nb_part+1-1 = 0
				 // If we only find one, i = nb_part-2. Thus we return nb_part - i - 1 = nb_part - (nb_part - 2) - 1 =nb_part - nb_part + 2 - 1 = 1
}



static void remove_child(struct link_list *parent, int idx){

	if(parent == NULL)
	{
		if(root == NULL){
			init_root();
		}
		parent = root;
	}
	assert(idx < parent->nb_valid_childs);

	if(parent->childs[idx].dns_name_part != NULL)
	{
		free(parent->childs[idx].dns_name_part);
		parent->childs[idx].dns_name_part = NULL;
	}
	if(parent->childs[idx].list_ip != NULL){
		free(parent->childs[idx].list_ip);
		parent->childs[idx].nb_ip = 0;
		parent->childs[idx].list_ip = NULL;
	}
	
	for(int i=0;i<parent->childs[idx]->nb_childs;++i){
		remove_child(&parent->childs[idx], i);
	}
	parent->childs[idx]->childs = NULL;

	parent->childs[idx] = parent->childs[nb_valid_elm - 1];
	parent->nb_valid_childs--;

}
static link_list *add_child(struct link_list *parent, char *dns_part){
	if(parent == NULL)
	{
		if(root == NULL){
			init_root();
		}
		parent = root;
	}

	if(parent->nb_valid_childs == parent->nb_childs){
		parent->childs = realloc(parent->childs,(parent->nb_childs+1)*sizeof(*(parent->childs)));//never free exept at the end of the program. TODO: limit of the size
		parent->nb_childs = 1 + parent->nb_childs;
	}
	parent->nb_valid_childs = parent->nb_valid_childs + 1

	parent->childs[parent->nb_valid_childs - 1].parent = parent;
	parent->childs[parent->nb_valid_childs - 1].list_ip = NULL;
	parent->childs[parent->nb_valid_childs - 1].nb_ip = 0;
	parent->childs[parent->nb_valid_childs - 1].timestamp = time(NULL);
	parent->childs[parent->nb_valid_childs - 1].ttl = 3600;
	
	int len_dns_part = strlen(dns_part);
	parent->childs[parent->nb_valid_childs - 1].dns_name_part = calloc(len_dns_part+1,sizeof(char)); // freed with remove_child()
	strncpy(parent->childs[parent->nb_valid_childs - 1].dns_name_part, dns_part, len_dns_part);

	//control
	for(int j=0;j<len_dns_part;++j){
		assert(parent->childs[parent->nb_valid_childs - 1].dns_name_part[j] == dns_part[j]);
	}
	assert(parent->childs[parent->nb_valid_childs - 1].dns_name_part[len_dns_part] == '\0');

	return &parent->childs[parent->nb_valid_childs - 1];

}

static int is_ip_in_list(struct link_list *in, uint32_t ip){
	for(int i=0; i<in->nb_ip;++i){
		if(in->list_ip[i] == ip)
			return TRUE;
	}
	return FALSE;
}

// OK here
static int is_valid(struct link_list *in){
	time_t timestamp_current = time(NULL);
	time_t timestamp_diff = timestamp_current - in->timestamp;
	if(timestamp_diff > in->ttl){
		int idx = find_child_by_ref(in);
		remove_child(in->parent,idx);
		return FALSE;
	}
	return TRUE;
}

// --------------------------------------------------------------------------------------------

struct link_list *add_entry(unsigned char *dns_name){

	int nb_parts = 0;
	char **splitted_dns_name = split_dns(dns_name, &nb_parts); // freeed in the end of this function


	struct link_list **founds = calloc(nb_parts, sizeof(*found));
	struct link_list *last_found = NULL;

	int nb_found = find_in_cache(splitted_dns_name, nb_parts, founds,0);
	last_found = founds[nb_found-1];

	if(nb_found == nb_parts){
		return last_found;
	} else {
		for(int i=nb_parts;i<nb_found;++i){
			last_found = add_child(last_found,splitted_dns_name[i]);
			assert(last_found != NULL || i == nb_found - 1);
		}
	}

	free(founds);
	free_splitted_dns(splitted_dns_name,nb_parts);
	splitted_dns_name = NULL;
	nb_parts = 0;

}

void add_ip(struct link_list *in, uint32_t ip){
	char ip_str[256];
	convert_b32_to_str(ip_str, ip);

	if(is_ip_in_list(in, ip) == TRUE){
		printf("IP %s for domain %s EXIST\n",ip_str, in->dns_name);
		return;
	}
	in->nb_ip++;
	in->list_ip = calloc(in->nb_ip,sizeof(*(in->list_ip)));
	in->list_ip[in->nb_ip - 1] = ip;


	printf("Add IP %s for domain %s\n",ip_str, in->dns_name);
}

/*void add_multiple_ip(struct entry *in, uint32_t *ip, int nb_ips){
	for(int i=0;i<nb_ips;++i){
		add_ip(in,ip[i]); // This function check if ip exist before adding it
	}
}*/

void set_ttl(struct link_list  *in, uint32_t ttl){
	in->ttl = ttl;
}

int is_ip_allowed(uint32_t ip) {
	char ip_str[256];
	convert_b32_to_str(ip_str, ip);
	
	struct link_list *current = link_start;

	while(current != NULL){
		assert(current->in != NULL);
		for(int i=0 ; i < current->in->nb_ip ; ++i){
			if(current->in->list_ip[i] == ip){
				if(is_valid(current->in) == TRUE){
					printf("IP %s [%s]  ACCEPTED\n",ip_str, current->in->dns_name);
					return TRUE;
				}
			}
		}
		current = current->next;
	}
	printf("IP %s REJECT\n",ip_str);
	return FALSE; // We didn't find the IP OR the IP is out of delay
}

void set_log_file(FILE *file){
	log_file = file;
}
