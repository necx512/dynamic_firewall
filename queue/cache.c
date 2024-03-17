#define TRUE 1
#define FALSE 0

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <assert.h>

#include "cache.h"

static struct link_list *link_start= NULL;
static int nb_entries = 0;

static void free_entry(struct entry *in){
	struct link_list *current = link_start;
	while(current != NULL) {
		if(current->in == in) {

			free(current->in->dns_name);
			current->in->dns_name = NULL;

			free(current->in->list_ip);
			current->in->list_ip = NULL;

			free(current->in);
			current->in = NULL;

			//unlink
			current->prev->next = current->next;
			current->next->prev = current->prev;

			nb_entries--;
			if(nb_entries == 0){
				free(link_start);
				link_start = NULL;
			}

			break;
		}
	}

}

static struct entry *find_in_cache(unsigned char *dns_name){

	struct link_list *current = link_start;
	while(current != NULL){
		assert(current->in != NULL);
		if(strcmp((char *)current->in->dns_name, (char *)dns_name)==0){
			return current->in;
		}
	}
	return NULL;
}
static int is_ip_in_list(struct entry *in, uint32_t ip){
	for(int i=0; i<in->nb_ip;++i){
		if(in->list_ip[i] == ip)
			return TRUE;
	}
	return 0;
}


static struct entry *create_new_entry(unsigned char *dns_name){

	struct entry *in = calloc(1, sizeof(*in));

	int len_str=strlen((char *)dns_name);
	in->dns_name = calloc(len_str+1,1);
	strncpy((char *)in->dns_name, (char *)dns_name,len_str);

	in->list_ip = NULL;
	in->nb_ip = 0;
	in->ttl = 3600;
	in->timestamp = time(NULL);

	struct link_list *new_elm = calloc(1,sizeof(*link_start));
	new_elm->in = in;
	new_elm->prev = NULL;

	if(link_start == NULL){
		link_start = new_elm;
		link_start->next = NULL; //=>new_elm->next=NULL
	}
	else{
		new_elm->next = link_start;
		link_start->prev = new_elm;
		link_start = new_elm;
	}
	nb_entries++;

	return in;
}
static int is_valid(struct entry *in){
	time_t timestamp_diff = time(NULL) - in->timestamp;
	if(timestamp_diff <= in->ttl){
		free_entry(in);
		return TRUE;
	}
	return FALSE;
}

// --------------------------------------------------------------------------------------------

struct entry *add_entry(unsigned char *dns_name){
	struct entry *in = find_in_cache(dns_name);
	if(in != NULL){
		return in;
	}

	return create_new_entry(dns_name);
}

void add_ip(struct entry *in, uint32_t ip){
	if(is_ip_in_list(in, ip) == TRUE){
		return;
	}
	in->nb_ip++;
	in->list_ip = calloc(in->nb_ip,sizeof(*(in->list_ip)));
	in->list_ip[in->nb_ip - 1] = ip;
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
	struct link_list *current = link_start;
	while(current != NULL){
		for(int i=0 ; i < current->in->nb_ip ; ++i){
			if(current->in->list_ip[i] == ip){
				if(is_valid(current->in) == TRUE){
					return TRUE;
				}
			}
		}
		current = current->next;
	}
	return FALSE; // We didn't find the IP OR the IP is out of delay
}
