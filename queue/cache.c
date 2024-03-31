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
void init_root(void){
	root = calloc(1,sizeof(*root)); // This will never be freed except at the end of the program.

	root->parent = NULL;

	root->childs = NULL;
	root->nb_valid_childs = 0;
	root->nb_childs = 0;

	root->list_ip = NULL;
	root->nb_ip = 0;
	root->dns_name_part = NULL;
	root->timestamp = 0;
	root->ttl = 0;
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

	*nb_parts = 0;


	for(int i=0;i<len_name+1;++i){
		if(i == len_name || dns_name[i] == '.') {
			if(len_part == 0)
				continue;
			parts = realloc(parts,(*nb_parts + 1)*sizeof(parts)); // to be freed -> free_splitted_dns()
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
		assert(root != NULL);
		parent = root;
	}
	int i;
	for(i=0; i < parent->nb_valid_childs ; ++i){
		if(strcmp(dns_part,parent->childs[i]->dns_name_part) == 0){
			break;
		}
	}
	return i;// if i == parent->nb_valid_childs => not found
}

/*static int find_child_by_ref(struct link_list *child){
	struct link_list *parent = child->parent;
	int i;
	for(i=0; i < parent->nb_valid_childs ; ++i){
		if((long)&parent->childs[i] == (long)child){
			break;
		}
	}
	return i;// if i == parent->nb_valid_childs => not found
}*/

static int find_in_cache(char **splitted_dns_name, int nb_parts, struct link_list **founds/* should be allocated*/, int only_last_found){
	struct link_list *parent = root;
	int i;
	for(i=nb_parts-1; i>=0;--i){
		int idx = find_child_by_dns_part(parent, splitted_dns_name[i]);
		if(idx < parent->nb_valid_childs){
			if(only_last_found == 1)
				*founds = parent->childs[idx];
			else
				founds[nb_parts - i - 1] = parent->childs[idx];
			parent = parent->childs[idx];
		} else {
			break;
		}
	}
	return nb_parts - i - 1; // If we find all, then i==-1. Thus, we return nb_part-i-1 = nb_part - (-1)-1 = nb_part + 1 - 1 = nbpart
				 // If we dont find it, i=nb_part-1. Thus we return nb_part-i-1 = nb_part-(nb_part-1)-1=nb_part-nb_part+1-1 = 0
				 // If we only find one, i = nb_part-2. Thus we return nb_part - i - 1 = nb_part - (nb_part - 2) - 1 =nb_part - nb_part + 2 - 1 = 1
}



static void remove_child(struct link_list *elm){

	//free childs
	int nb_elements = elm->nb_valid_childs;
	for(int i=0;i<nb_elements;++i){
		remove_child(elm->childs[i]);
	}
	assert(elm->nb_valid_childs == 0);

	if(elm->nb_childs != 0)
		free(elm->childs);
	
	if(elm->dns_name_part != NULL){
		free(elm->dns_name_part);
		elm->dns_name_part = NULL;
	}
	if(elm->list_ip != NULL) {
		free(elm->list_ip);
		elm->list_ip = NULL;
	}


	//detach from parent
	struct link_list *parent = elm->parent;
	if(parent != NULL){
		assert(parent->childs[elm->child_idx] == elm);
		parent->childs[parent->nb_valid_childs - 1]->child_idx = elm->child_idx;
		parent->childs[elm->child_idx] = parent->childs[parent->nb_valid_childs - 1];
		parent->nb_valid_childs--;
	}
	free(elm);

}
void free_root(void){
	assert(root != NULL);
	int nb_valid_childs = root->nb_valid_childs;
	for(int i=0;i<nb_valid_childs;++i){
		remove_child(root->childs[i]);
	}
	if(root->nb_childs != 0)
		free(root->childs);
	free(root);
	root = NULL;
}
static struct link_list *add_child(struct link_list *parent, char *dns_part){
	if(parent == NULL)
	{
		assert(root != NULL);
		parent = root;
	}

	if(parent->nb_valid_childs == parent->nb_childs){
		parent->childs = realloc(parent->childs,(parent->nb_childs+1)*sizeof(*(parent->childs)));//never free exept at the end of the program. TODO: limit of the size
		parent->nb_childs = 1 + parent->nb_childs;
	}
	parent->nb_valid_childs = parent->nb_valid_childs + 1;

	parent->childs[parent->nb_valid_childs - 1] = calloc(1,sizeof(*(parent->childs[parent->nb_valid_childs - 1])));

	parent->childs[parent->nb_valid_childs - 1]->parent = parent;
	parent->childs[parent->nb_valid_childs - 1]->list_ip = NULL;
	parent->childs[parent->nb_valid_childs - 1]->nb_ip = 0;
	parent->childs[parent->nb_valid_childs - 1]->timestamp = time(NULL);
	parent->childs[parent->nb_valid_childs - 1]->ttl = 3600;
	
	int len_dns_part = strlen(dns_part);
	parent->childs[parent->nb_valid_childs - 1]->dns_name_part = calloc(len_dns_part+1,sizeof(char)); // freed with remove_child()
	strncpy(parent->childs[parent->nb_valid_childs - 1]->dns_name_part, dns_part, len_dns_part);

	//control
	for(int j=0;j<len_dns_part;++j){
		assert(parent->childs[parent->nb_valid_childs - 1]->dns_name_part[j] == dns_part[j]);
	}
	assert(parent->childs[parent->nb_valid_childs - 1]->dns_name_part[len_dns_part] == '\0');

	return parent->childs[parent->nb_valid_childs - 1];

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
		remove_child(in);
		return FALSE;
	}
	return TRUE;
}

// --------------------------------------------------------------------------------------------

struct link_list *add_entry(char *dns_name){

	int nb_parts = 0;
	char **splitted_dns_name = split_dns(dns_name, &nb_parts); // freeed in the end of this function


	struct link_list **founds = calloc(nb_parts, sizeof(*founds)); //freed at the end of this function
	struct link_list *last_found = NULL;

	int nb_found = find_in_cache(splitted_dns_name, nb_parts, founds,0); // can be 0 to nb_parts
	if(nb_found == 0)
		last_found = root;
	else
		last_found = founds[nb_found-1];


	if(nb_found == nb_parts){
		return last_found;
	} else {
		for(int i=nb_found;i<nb_parts;++i){
			printf("Adding %s to %s\n",splitted_dns_name[nb_parts-i-1],last_found->dns_name_part);
			last_found = add_child(last_found,splitted_dns_name[nb_parts-i-1]);
			assert(last_found != NULL || i == nb_found - 1);
		}
	}

	free(founds);
	free_splitted_dns(splitted_dns_name,nb_parts);
	splitted_dns_name = NULL;
	nb_parts = 0;

	return last_found;



}
static void print_complete_dns_from_bottom_item(struct link_list *in){
	struct link_list *current = in;
	while(current->parent != root){
		printf("%s.",current->dns_name_part);
		current = current->parent;
	}
	printf("%s\n",current->dns_name_part);

}
static void print_item(struct link_list *in){
	char strret[256];
	print_complete_dns_from_bottom_item(in);
	printf("\tnb_ip = %d\n",in->nb_ip);
	for(int i=0;i<in->nb_ip;++i){
	        convert_b32_to_str(strret, ntohl(in->list_ip[i]));
		printf("\t\t%s\n",strret);
	}
	printf("\ttimestamp = %ld\n",in->timestamp);
	printf("\tttl = %d\n",in->ttl);
	if(is_valid(in) == TRUE){
		printf("\tis_valid : TRUE\n");
	} else {
		printf("\tis_valid : FALSE. This node has been deleted just after checking the validity and will not print again\n");
	}
}

void print_tree(struct link_list *origin){
	if(origin == NULL)
		origin = root;
	if(origin != root && origin->nb_valid_childs == 0){
		print_item(origin);
	} else {
		for(int i=0;i<origin->nb_valid_childs;++i){
			assert(origin->childs[i] != NULL);
			print_tree(origin->childs[i]);
		}
	}
}

void add_ip(struct link_list *in, uint32_t ip){
	char ip_str[256];
	convert_b32_to_str(ip_str, ip);

	if(is_ip_in_list(in, ip) == TRUE){
		printf("IP %s for domain %s EXIST\n",ip_str, in->dns_name_part);
		return;
	}
	in->nb_ip++;
	in->list_ip = calloc(in->nb_ip,sizeof(*(in->list_ip)));
	in->list_ip[in->nb_ip - 1] = ip;


	printf("Add IP %s for domain %s\n",ip_str, in->dns_name_part);
}

/*void add_multiple_ip(struct entry *in, uint32_t *ip, int nb_ips){
	for(int i=0;i<nb_ips;++i){
		add_ip(in,ip[i]); // This function check if ip exist before adding it
	}
}*/

/*static void set_ttl(struct link_list  *in, uint32_t ttl){
	in->ttl = ttl;
}*/

int is_ip_allowed(uint32_t ip, struct link_list  *current) {
	if(current == NULL){
		assert(root != NULL);
		if(root->nb_valid_childs < 1)
			current = NULL;
		else { 
			current = root;
		}
	}
	if(current != NULL){
		for(int i=0;i<current->nb_ip;++i){
			if(current->list_ip[i] == ip)
				return TRUE;
		}
		for(int i=0;i<current->nb_valid_childs;++i){
			if(is_ip_allowed(ip,current->childs[i]) == TRUE)
				return TRUE;
		}
	}
	return FALSE;
}

void set_log_file(FILE *file){
	log_file = file;
}

#ifdef TEST
int main(){
	init_root();
	assert(root != NULL);


	char strret[256];
	uint32_t nbr = ntohl(0x11223344);
	convert_b32_to_str(strret, 0x11223344);
	assert(strcmp(strret,"68.51.34.17") == 0);
	printf("\e[92mconvert_b32_to_str OK\e[0m\n");




	// split_dns
	// free_splitted_dns by valgrind
	int nb_parts = 0;
	char **parts = NULL;
	
	parts = split_dns("google.fr", &nb_parts);
	assert(nb_parts == 2);
	assert(strcmp(parts[0],"google") == 0);
	assert(strcmp(parts[1],"fr") == 0);
	free_splitted_dns(parts,nb_parts);

	parts = split_dns("meteo.com", &nb_parts);
	assert(nb_parts == 2);
	assert(strcmp(parts[0],"meteo") == 0);
	assert(strcmp(parts[1],"com") == 0);
	free_splitted_dns(parts,nb_parts);
	
	parts = split_dns("abc.de.fe.jud.sez", &nb_parts);
	assert(nb_parts == 5);
	assert(strcmp(parts[0],"abc") == 0);
	assert(strcmp(parts[1],"de") == 0);
	assert(strcmp(parts[2],"fe") == 0);
	assert(strcmp(parts[3],"jud") == 0);
	assert(strcmp(parts[4],"sez") == 0);
	free_splitted_dns(parts,nb_parts);
	
	parts = split_dns("google.fr.", &nb_parts);
	assert(nb_parts == 2);
	assert(strcmp(parts[0],"google") == 0);
	assert(strcmp(parts[1],"fr") == 0);
	free_splitted_dns(parts,nb_parts);
	
	parts = split_dns("google.fr..", &nb_parts);
	assert(nb_parts == 2);
	assert(strcmp(parts[0],"google") == 0);
	assert(strcmp(parts[1],"fr") == 0);
	free_splitted_dns(parts,nb_parts);
	
	parts = split_dns("google..fr", &nb_parts);
	assert(nb_parts == 2);
	assert(strcmp(parts[0],"google") == 0);
	assert(strcmp(parts[1],"fr") == 0);
	free_splitted_dns(parts,nb_parts);
	
	parts = split_dns(".google.fr", &nb_parts);
	assert(nb_parts == 2);
	assert(strcmp(parts[0],"google") == 0);
	assert(strcmp(parts[1],"fr") == 0);
	free_splitted_dns(parts,nb_parts);
	
	printf("\e[92msplit_dns OK\e[0m\n");



	// add child
	// remove_child
	struct link_list *elm = add_child(NULL, "com");
	assert(strcmp(elm->dns_name_part,"com") == 0);
	assert(root->nb_valid_childs == 1);
	remove_child(elm);
	printf("\e[92madd_child / remove_child OK\e[0m\n");


	// Manually add
	struct link_list *elm_com = add_child(NULL, "com");
	struct link_list *elm_google = add_child(elm_com,"google");
	struct link_list *elm_a = add_child(elm_google,"a");
	struct link_list *elm_heliott = add_child(elm_a,"heliott");

	assert(strcmp(elm_com->dns_name_part,"com") == 0);
	assert(strcmp(elm_google->dns_name_part,"google") == 0);
	assert(strcmp(elm_a->dns_name_part,"a") == 0);
	assert(strcmp(elm_heliott->dns_name_part,"heliott") == 0);

	assert(elm_google->parent == elm_com);
	assert(elm_a->parent == elm_google);
	assert(elm_heliott->parent == elm_a);

	assert(elm_com->nb_valid_childs == 1);
	assert(elm_com->childs[0] == elm_google);

	assert(elm_google->nb_valid_childs == 1);
	assert(elm_google->childs[0] == elm_a);

	assert(elm_a->nb_valid_childs == 1);
	assert(elm_a->childs[0] == elm_heliott);

	assert(elm_heliott->nb_valid_childs == 0);


	remove_child(elm_heliott);
	remove_child(elm_a);
	remove_child(elm_google);
	remove_child(elm_com);
	
	// Test remove_child complete
	elm_com = add_child(NULL, "com");
	elm_google = add_child(elm_com,"google");

	assert(strcmp(elm_com->dns_name_part,"com") == 0);
	assert(strcmp(elm_google->dns_name_part,"google") == 0);

	assert(elm_google->parent == elm_com);

	assert(elm_com->nb_valid_childs == 1);
	assert(elm_com->childs[0] == elm_google);

	assert(elm_google->nb_valid_childs == 0);

	remove_child(elm_com);


	// Testing multiple childs
	elm_com = add_child(NULL, "com");
	elm_google = add_child(elm_com,"google");
	struct link_list *elm_youtube = add_child(elm_com,"youtube");
	assert(strcmp(elm_com->dns_name_part,"com") == 0);
	debug=1;
	remove_child(elm_com);


	// find_child_by_dns_part
	elm_com = add_child(NULL, "com");
	elm_google = add_child(elm_com,"google");
	elm_youtube = add_child(elm_com,"youtube");
	
	int idx = find_child_by_dns_part(elm_com, "google");
	assert(idx == 0);
	assert(strcmp(elm_com->childs[idx]->dns_name_part,"google")==0);
	
	idx = find_child_by_dns_part(elm_com, "youtube");
	assert(idx == 1);
	assert(strcmp(elm_com->childs[idx]->dns_name_part,"youtube")==0);

	remove_child(elm_com);
	

	//find_in_cache
	elm_com = add_child(NULL, "fr");
	elm_google = add_child(elm_com,"google");
	
	nb_parts = 0;
        parts = split_dns("google.fr", &nb_parts);

	struct link_list **founds = calloc(nb_parts,sizeof(*founds));
	
	int nb_parts_ret = find_in_cache(parts, nb_parts, founds, 0);
	assert(nb_parts_ret == nb_parts);
	assert(strcmp(founds[0]->dns_name_part, "fr") == 0);
	assert(strcmp(founds[1]->dns_name_part, "google") == 0);

	remove_child(elm_com);
	nb_parts_ret = find_in_cache(parts, nb_parts, founds, 0);
	assert(nb_parts_ret == 0);


	free_splitted_dns(parts,nb_parts);
	free(founds);


	



	free_root();



	//////////////////////////////////
	init_root();
	struct link_list *new_entry_google_fr = add_entry("google.fr");
	struct link_list *new_entry_meteo_fr = add_entry("meteo.fr");
	struct link_list *new_entry_test_meteo_fr = add_entry("test.meteo.fr");
	struct link_list *new_entry_test_meteo_com = add_entry("test.meteo.net");

	add_ip(new_entry_google_fr,0x11223344);

	set_ttl(new_entry_test_meteo_com, 5);

	/*printf("===============================\n");
	print_item(new_entry_google_fr);
	printf("\n");
	
	printf("===============================\n");
	print_item(new_entry_meteo_fr);
	printf("\n");
	
	printf("===============================\n");
	print_item(new_entry_test_meteo_fr);
	printf("\n");

	printf("===============================\n");
	print_item(new_entry_test_meteo_com);
	printf("\n");*/
	printf("================= PRINT TREE ==========================\n");
	print_tree(NULL);
	sleep(10);
	printf("================= PRINT TREE ==========================\n");
	print_tree(NULL);
	printf("================= PRINT TREE ==========================\n");
	print_tree(NULL);

//	remove_child(root->childs[0]);
	free_root();




	return 0;



}
#endif
