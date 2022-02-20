#ifndef __SERVER_API_H
#define __SERVER_API_H

// 网络使用的库
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

// 下面正式进入网络编程
#include "basic_algorithm.h"
#include "thread_pool.h"
#include "all_def.h"
#include "string.h"
#include "structure_to_bytes.h"

#define MAX_LINE_BUFFER_THREAD 4096

void start_main_server(struct config_structure* config_stru_example, threadpool IDP_thread_pool);

#endif