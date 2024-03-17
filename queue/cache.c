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

static struct link_list *link_start=NULL;
static int nb_entries = 0;
static FILE *log_file = NULL;

static struct link_list *split_dns( char *complete_name){
	struct link_list *base = NULL;
	struct link_list *last = NULL;

        int max_size = strlen(complete_name);

        char *tmp = calloc(max_size,sizeof(*tmp));
        int idx_tmp = max_size-1;

        for(int i=max_size-1;i>=-1;--i){
                if(complete_name[i] == '.'  || i == -1){
                        int len_name = max_size-1 - idx_tmp;
                        printf("%d\n",len_name);
                        char *subdns_name = calloc(len_name+1,sizeof(*subdns_name));
                        memcpy(subdns_name,&tmp[idx_tmp+1],len_name);
			assert(strlen(subdns_name) == len_name);
                        printf("+%s+\n",subdns_name);

			/**/ 
			struct link_list *elm = calloc(1,sizeof(*elm));
			elm->next = NULL;
			elm->prev = NULL;
			elm->parent = last;
			elm->childs = NULL;
			elm->list_ip = NULL;
			elm->nb_ip = 0;
			elm->dns_name = subdns_name;
			elm->timestamp = time(NULL);
			elm->ttl = 3600;
			/**/


			if(base == NULL)
				base = elm;

			if(last != NULL){
				last->childs = elm; 
			}

			last = elm;

                        idx_tmp = max_size-1;
                } else {
                        printf("%p %c\n",&tmp[idx_tmp], complete_name[i]);
                        tmp[idx_tmp] = complete_name[i];
                        idx_tmp--;
                }
        }
	return base;
}

void free_subdns(struct link_list *entry){
	if(entry == NULL)
		return;

	if(entry->prev == NULL && entry->next == NULL){
		if(entry->parent != NULL)
			entry->parent->childs = NULL;
	} else {
		if(entry->prev != NULL)
			entry->prev->next = entry->next;
		if(entry->next != NULL)
			entry->next->prev = entry->prev;
	}

	free_subdns(current->next);
	current->next = NULL;

	free_subdns(current->prev);
	current->prev = NULL;

	free_subdns(current->child);
	current->child = NULL;

	free(current->dns_name);
	current->dns_name = NULL;

	free(entry);
}


static void convert_b32_to_str(char strret[256], uint32_t nbr){
	int nbr_a = (nbr>>0)&0xff;
	int nbr_b = (nbr>>8)&0xff;
	int nbr_c = (nbr>>16)&0xff;
	int nbr_d = (nbr>>24)&0xff;
	memset(strret,0,256);
	sprintf(strret,"%d.%d.%d.%d",nbr_a,nbr_b,nbr_c,nbr_d);
}

static int find_in_cache(struct link_list *base, struct link_list **last_found, struct link_list **ret_base){

	struct link_list *item = base;
	struct link_list *current = link_start;

	*last_found = NULL;
	*ret_base = NULL;

	while(item != NULL && current != NULL){
		while(current != NULL){
			if(strcmp((char *)current->dns_name, (char *)item->dns_name)==0){
				*last_found = current;
				*ret_base = item;
				break;
			}
			current=current->next;
		}
		if(current != NULL) // we found it
		{
			item = item->child; // item != NULL because this is the loop condition and item does not change in the inner loop
			current = current->child;
		}
		// else the loop will stop
	}

	if(item == NULL && current != NULL){
		return 1;
	}
	if(item != NULL && current == NULL){
		return 2;
	}
	if(item == NULL && current == NULL){
		return 0;
	}
}

static int is_ip_in_list(struct link_list *in, uint32_t ip){
	for(int i=0; i<in->nb_ip;++i){
		if(in->list_ip[i] == ip)
			return TRUE;
	}
	return 0;
}


static struct link_list *create_new_entry(unsigned char *dns_name){

	struct link_list *base = split_dns(dns_name);
	struct link_list *ret_base = NULL;

	struct link_list *elm = find_in_cache(base,&ret_base);
	if(elm != NULL)
		assert(ret_base != NULL);

	if(found)
		free_subdns(base);
		return
	else
		add_child(elm, ret_base->childs);


	struct link_list *find_in_cache(unsigned char *dns_name);

	return in;
}
static int is_valid(struct entry *in){
	time_t timestamp_current = time(NULL);
	time_t timestamp_diff = timestamp_current - in->timestamp;
	if(timestamp_diff > in->ttl){
		free_entry(in);
		return FALSE;
	}
	return TRUE;
}

// --------------------------------------------------------------------------------------------

struct entry *add_entry(unsigned char *dns_name){
	struct entry *in = find_in_cache(dns_name);
	if(in != NULL){
		//printf("Exist Entry for domain %s\n",dns_name);
		return in;
	}
	printf("\e[91mAdd Entry for domain %s. NbEntry before adding: %d\e[0m\n",dns_name,nb_entries);
	if(log_file != NULL)
	{
		printf("LOGGED\n");
		fprintf(log_file,"\e[91mAdd Entry for domain %s. NbEntry before adding: %d\e[0m\n",dns_name,nb_entries);
		fflush(log_file);
	}
	return create_new_entry(dns_name);
}

void add_ip(struct entry *in, uint32_t ip){
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

void set_ttl(struct entry *in, uint32_t ttl){
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
