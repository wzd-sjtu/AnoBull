#ifndef __NET_API_H
#define __NET_API_H

// renew the total project
#include "/usr/local/include/pbc/pbc.h"
#include "/usr/local/include/pbc/pbc_test.h"

#include "protocol_structure.h"
#include "net_config.h"
#include "all_def.h"
#include "stdlib.h"
#include "structure_to_bytes.h"


#include <sys/stat.h>
#include <sys/epoll.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/select.h>
#include <linux/netfilter_ipv4.h>
#include <stdarg.h>


int connect_IDP_server();
struct public_key_IDP* ask_pk_IDP(int sockfd, char* buf_recv, char* buf_send);
struct list* ask_user_info_infra(int sockfd, char* buf_recv, char* buf_send);
void fill_up_user_info(char* input_buffer, struct list* user_info_infra, int input_length_limit);
void fill_up_user_info_automatic(char* input_buffer, struct list* user_info_infra, int input_length_limit);

int send_user_info_to_IDP(int sockfd, char* buf_recv, char* buf_send, struct list* user_info_infra);
struct sigma_c* ask_compute_sigma_c(int sockfd, char* buf_recv, char* buf_send, struct public_key_IDP* tmp_pk_IDP);
#endif