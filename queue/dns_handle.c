#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <arpa/inet.h>

#include "dns_handle.h"

struct dns_replies *export_dns_replies(struct dnshdr *dnshdr, struct dns_queries *queries){
	unsigned char *ptr_reply = (unsigned char *) (dnshdr + 1);
	ptr_reply += queries->length;

	struct dns_replies *replies = malloc(sizeof(*replies));
	replies->nb_replies = ntohs(dnshdr->rep_num);
	replies->entries = malloc( (replies->nb_replies) * sizeof(struct dns_reply_entry));


	for(int reply_idx = 0 ; reply_idx < replies->nb_replies ; ++reply_idx){

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

struct dns_queries *export_dns_queries(struct dnshdr *dnshdr){
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

void free_dns_queries(struct dns_queries **queries_top){
	struct dns_queries *queries = *queries_top;
	for(int query_idx = 0 ; query_idx < queries->nb_queries ; ++query_idx){
		free(queries->entries[query_idx].name);
		queries->entries[query_idx].name = NULL;
	}
	free(queries->entries);
	queries->entries = NULL;

	free(*queries_top);
	*queries_top = NULL;


}

void free_dns_replies(struct dns_replies **replies_top){
	struct dns_replies *replies = *replies_top;
	for(int reply_idx = 0 ; reply_idx < replies->nb_replies ; ++reply_idx){
		free(replies->entries[reply_idx].data);
		replies->entries[reply_idx].data = NULL;
	}
	free(replies->entries);
	replies->entries = NULL;

	free(*replies_top);
	*replies_top = NULL;




}
