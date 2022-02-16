// 需要一边写程序一边进行测试
#include "main.h"
#include "test.h"
#include "read_config.h"
#include "all_def.h"


#include "/usr/local/include/pbc/pbc.h"
#include "/usr/local/include/pbc/pbc_test.h"
#include "stdio.h"
#include "stdlib.h"
#include <string.h>
#include <openssl/sha.h>

#include "global.h"

// 需要使用的算法
#include "basic_algorithm.h"

#include "thread_pool.h"

#define LISTENQ 10
int tcp_listen(int port)
{
	struct sockaddr_in cl_addr,proxyserver_addr;
	socklen_t sin_size = sizeof(struct sockaddr_in);
	int sockfd, accept_sockfd, on = 1;

	/* Build address structure to bind to socket. */
	memset(&proxyserver_addr, 0, sizeof(proxyserver_addr));							// zero proxyserver_addr
	proxyserver_addr.sin_family = AF_INET;
	proxyserver_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	proxyserver_addr.sin_port = htons(port);

	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);			// create socket
	if (sockfd < 0) {
		printf("Socket failed...Abort...\n");
		return -1;
	}
	/* Set socket to be reusable */
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on));

	if (bind(sockfd, (struct sockaddr *) &proxyserver_addr, sizeof(proxyserver_addr)) < 0) {
		printf("Bind failed...Abort...\n");
		return -1;
	}
	if (listen(sockfd, LISTENQ) < 0) {
		printf("Listen failed...Abort...\n");
		return -1;
	}
	return sockfd;
}

void Thread_function(void* arg) {

    int clifd,servfd;
	clifd=(int)(arg);

    printf("this is thread %d\n", clifd);

    return;
}
int main() {
    // 整个程序的主架构
    // socket需要参考csapp做对应的改编
    // 从而提升程序的运行效率

    // 编码过程中的测试环节
    test_all();

    // 配置信息初始化，首先采取手动输入的方式编写
    struct config_structure* test_config_specific = init_test_config();

    struct config_structure* ok_config = read_config_init();
    // 打印所选择的椭圆曲线
    // printf(test_config_specific->Elliptic_Curve_Selection);
    printf("config set init successfully!\n");

    // pairing_t* init_space(char* curve_name);
    // struct secret_key_IDP* init_IDP_secret_key(pairing_t* pairing);
    // struct public_key_IDP* init_IDP_public_key(pairing_t* pairing, int N, struct secret_key_IDP* sk_IDP);

    pairing_t* pair_choice = init_space(test_config_specific->Elliptic_Curve_Selection);
    sk_IDP = init_IDP_secret_key(pair_choice);
    int info_dimention = test_config_specific->user_info_list->list_num;
    pk_IDP = init_IDP_public_key(pair_choice, info_dimention, sk_IDP);
    printf("Gene public_key and Gene secret_key successfully!\n");


    // 初始化thread_pool 线程池
    // 线程池数据结构
    // typedef struct thpool_* threadpool;
    
    // 这里有个小问题，用的是uint转换为int，可能会存在溢出？
    threadpool IDP_thread_pool = thpool_init((int)test_config_specific->max_connect_thread_number_num);
    // 线程池API
    // int thpool_add_work(threadpool, void (*function_p)(void*), void* arg_p);
    // void thpool_wait(threadpool);
    // int thpool_num_threads_working(threadpool);
    // 很显然，线程池要远比自定义的多线程好用

    // 正式开始网络编程
    // 用户地址？并不重要
	struct sockaddr_in cli_addr;
	socklen_t sin_size = sizeof(struct sockaddr_in);
    int connfd,sockfd;

    // 监听端口
    int port = (int)test_config_specific->port_num;

    // 网络库的封装在这里非常地粗浅，先跑起来再说
    sockfd=tcp_listen(port);
    printf("listening on %d\n",port);
	
    // 正式进入while循环服务器
	for(;;) {
		connfd=accept(sockfd,(struct sockaddr *)&cli_addr, &sin_size);
		if(connfd<0) {
			printf("accept error.\n");
			continue;
		}
		else {
			printf("generate the new socket connfd: %d \n", connfd);
		}
        // int thpool_add_work(threadpool, void (*function_p)(void*), void* arg_p);
        thpool_add_work(IDP_thread_pool, Thread_function, (void*)connfd);
	}

    return 0;
}