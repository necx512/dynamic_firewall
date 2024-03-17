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

static struct link_list *link_start= NULL;
static int nb_entries = 0;

static void free_entry(struct entry *in){
	printf("Free entry %d\n",nb_entries);
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
			if(current->prev != NULL)
				current->prev->next = current->next;


			if(current->next != NULL)
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

static void convert_b32_to_str(char strret[256], uint32_t nbr){
	int nbr_a = (nbr>>0)&0xff;
	int nbr_b = (nbr>>8)&0xff;
	int nbr_c = (nbr>>16)&0xff;
	int nbr_d = (nbr>>24)&0xff;
	memset(strret,0,256);
	sprintf(strret,"%d.%d.%d.%d",nbr_a,nbr_b,nbr_c,nbr_d);
}

static struct entry *find_in_cache(unsigned char *dns_name){
	struct link_list *current = link_start;
	while(current != NULL){
		assert(current->in != NULL);
		if(strcmp((char *)current->in->dns_name, (char *)dns_name)==0){
			return current->in;
		}
		current=current->next;
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
		printf("Exist Entry for domain %s\n",dns_name);
		return in;
	}
	printf("Add Entry for domain %s\n",dns_name);
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
	printf("is_ip_allowed for IP %s\n",ip_str);
	
	struct link_list *current = link_start;

	while(current != NULL){
		assert(current->in != NULL);
		for(int i=0 ; i < current->in->nb_ip ; ++i){
			if(current->in->list_ip[i] == ip){
				if(is_valid(current->in) == TRUE){
					printf("----->Connection %s %s allowed\n", current->in->dns_name, ip_str); 
					return TRUE;
				}
			}
		}
		current = current->next;
	}
	printf("REJECT\n");
	return FALSE; // We didn't find the IP OR the IP is out of delay
}
