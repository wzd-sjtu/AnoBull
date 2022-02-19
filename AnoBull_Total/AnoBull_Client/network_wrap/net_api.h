#ifndef __NET_API_H
#define __NET_API_H

// renew the total project
#include "protocol_structure.h"
#include "net_config.h"
#include "all_def.h"
#include "stdlib.h"


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

#endif