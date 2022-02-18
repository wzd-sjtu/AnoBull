#include "server_api.h"

// 重复听的次数
#define LISTENQ 10
#define HEADER_LEN 4
#define DATA_LEN 3068

// 公钥+私钥设置为全局变量
#include "global.h"

// socket+bind+listen
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

    // 经过一系列处理，得到用户的客户端程序，之后需要进行别的操作behavour
    // 关于发送信息的解码方式？
    // 仅仅在客户端进行设计即可，这是非常明晰的了
    int clifd;
	clifd=(int)(arg);

    // 下面正式进入了多线程模型之中

    printf("this is thread %d\n", clifd);

    // 网络编程缓冲区
    char thread_buffer[MAX_LINE_BUFFER_THREAD];
    // char thread_buffer_send[MAX_LINE_BUFFER_THREAD];

    // 后面需要设计网络协议，封装有关的socket接口

    char header_buffer[HEADER_LEN];
    int total_data_len = 0;
    char data_buffer[DATA_LEN];
    // 再往下就是设计协议了，令人费解

    // 关于读取数据？
    int state = -1;

    // 协议状态机的内部定义
    // 0/1/2/3/4/5/6/7
    // 0表示无效，invaid
    // 10表示收到，也就是一个回复，是最基本的回复信息
    // 1表示公钥
    // 2表示用户要填写的信息结构
    // 3表示用户的信息序列串
    // 4表示需要计算 签名，获取对应的签名
    // 4必须在3后面，这个是状态机的自动转换过程

    int length = 0;

    while(1) {
        // 阻塞了网络，需要重新载入
        // 并不明白如何进行网络编程
        // 需要进行结构体的转换
        length = read(clifd, thread_buffer, MAX_LINE_BUFFER_THREAD);

        if(length <= 0) return;

        // 头文件填入
        memcpy(thread_buffer, header_buffer, HEADER_LEN);
        int tmp_len = (thread_buffer[1] >> 16); // 多余位一律补零
        memcpy(&thread_buffer[HEADER_LEN], &data_buffer[total_data_len], tmp_len);

        total_data_len += tmp_len;

        // 文件是否会分割？不妨默认为不会分割
        // 暂时状态比较少，不需要额外添加控制信息

        state = (thread_buffer[0] >> 24); // 左移24位，别的位补充0即可
        
        // 进入了核心逻辑区，state状态变量
        // 整体上是一问一答的处理logic，也不需要回ack，直接回一个header即可，
        switch(state){
            case 0: {
                // 输入不合理，表示失败了
                printf("invalud document\n");
                state = -1;
                return;
            }
            case 1: {
                // 客户端想要公钥，计算公钥并且存入buffer

                // send 完成之后，进入wait状态
                break;
            }
            case 2: {
                // 发送用户需要的信息串结构，按照标准写入buffer之中
            }
            case 3: {
                // 用户发来的信息串序列，这是最基本的内容
            }
            case 4: {
                // 用户请求计算签名，也就是论文中的sigma_c
            }
            default:printf("error\n"); break;
        }
        // 上文send完之后，将state归零or归为-1
        state = -1;
    }

    return;
}
// 正式开始网络编程

void start_main_server(struct config_structure* config_stru_example, threadpool IDP_thread_pool) {

    // 关于server里面需要进行的处理，全部封装为网络库，写在同一个文件里面

    struct sockaddr_in cli_addr;
	socklen_t sin_size = sizeof(struct sockaddr_in);
    int connfd,sockfd;

    // 监听端口
    int port = config_stru_example->port_num;

    // 网络库的封装在这里非常地粗浅，先跑起来再说
    sockfd=tcp_listen(port);
    printf("listening on %d\n",port);
	
    // 网络部分的架构不应该放在这一部分实现，位置有误
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
}