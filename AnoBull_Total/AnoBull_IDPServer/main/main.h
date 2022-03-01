#ifndef __MAIN_H
#define __MAIN_H
#define __GLOBALS

#include "test.h"
#include "global.h"


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


#include "sqlite.h"
#include "global.h"

#endif