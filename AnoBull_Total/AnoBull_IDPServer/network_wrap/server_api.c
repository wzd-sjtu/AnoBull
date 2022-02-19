#include "server_api.h"

// 重复听的次数
#define LISTENQ 10
#define HEADER_LEN 8
#define DATA_LEN 3064

// 公钥+私钥设置为全局变量
#include "global.h"
#include "protocol_structure.h"
#include "stdint_p.h"

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
    char thread_recv_buffer[MAX_LINE_BUFFER_THREAD] = {0};
    char thread_send_buffer[MAX_LINE_BUFFER_THREAD] = {0};
    // char thread_buffer_send[MAX_LINE_BUFFER_THREAD];

    // 后面需要设计网络协议，封装有关的socket接口
    int total_data_len = 0;
    // 再往下就是设计协议了，令人费解

    // 关于读取数据？
    int state = -1;

    // 最好填充一个enum枚举变量，仅仅使用文字描述非常不直观
    // 协议状态机的内部定义
    // 0/1/2/3/4/5/6/7
    // 0表示无效，invaid
    // 10表示收到，也就是一个回复，是最基本的回复信息，ack位可以不用等待了的
    // 1表示公钥
    // 2表示用户要填写的信息结构
    // 3表示用户的信息序列串
    // 4表示需要计算 签名，获取对应的签名
    // 4必须在3后面，这个是状态机的自动转换过程

    int length = 0;

    // printf("go into while\n");
    while(1) {
        // 阻塞了网络，需要重新载入
        // 并不明白如何进行网络编程
        // 需要进行结构体的转换

        // 具体过程就是不断recv再不断send的过程
        // 这个是多线程里面最核心的内容

        printf("begin recv:\n");
        length = recv(clifd, thread_recv_buffer, MAX_LINE_BUFFER_THREAD, 0);
        printf("receive length is %d\n", length);
        // 阻塞读入长度为0，出现了问题
        if(length <= 0) {
            printf("read failed!\n");
            return;
        }
        

        // 一旦读取到buffer，直接进入process_recv函数
        // 收到消息总要返回一些东西
        printf("begin compute the send thing!\n");
        length = process_recv(thread_recv_buffer, thread_send_buffer, length);
        printf("send length is %d\n", length);

        // (num=send(sockfd,buf,HEADER_LEN + tmp_header->length, 0)==-1)
        // length 即为最终的缓冲区长度
        length = send(clifd, thread_send_buffer, length, 0);

        if(length == -1) {
            printf("send failed!\n");
        }

    }

    return;
}


int compute_and_store_public_key(char* send_buffer, int data_len_limit) {
    // 这里进行的是公钥转换
    // printf("!!!!!!\n");
    int tmp_res = pk_IDP_to_bytes(send_buffer, data_len_limit);
    if(tmp_res == 0) return 0;

    // struct public_key_IDP* pk_IDP_from_bytes(unsigned char* data_buffer, int length);
    // int comapre_pk_IDP(struct public_key_IDP* pk_IDP, struct public_key_IDP* new_pk_IDP);

    // struct public_key_IDP* pk_IDP_from_bytes(data_buffer, 0);
    // 完成了内容转换
    return tmp_res;
}



int process_recv(char* thread_recv_buffer, char* thread_send_buffer, int recv_length) {
    // 指针强制类型转换
    struct protocol_header* recv_header = (struct protocol_header*)thread_recv_buffer;
    struct protocol_header* send_header = (struct protocol_header*)thread_send_buffer;

    // 发送头header清零
    memset(send_header, 0, sizeof(struct protocol_header));

    // header len已经固定为8bytes，不需要再次修改了
    char* send_buffer = (char*)(thread_send_buffer + HEADER_LEN);
    // 关键信息提取
    uint8_t_p data_len = recv_header->length;
    uint8_t_p now_state = recv_header->state;


    // 进入了核心逻辑区，state状态变量,需要加入无穷while循环及scanf输入判断

    
    switch(now_state){
        case 0: {
            // 输入不合理，表示失败了
            printf("invalud document\n");
            now_state = -1;
        }
        // 客户想要公钥，数据区不需要解析，只发送一个头就可以
        case 1: {
            // 客户端想要公钥，计算公钥并且存入buffer

            // 希望把缓冲区直接填入buffer里面，减少内容的复制粘贴
            // data_len是最大数据区长度

            int put_len = compute_and_store_public_key(send_buffer, DATA_LEN);
            // send 完成之后，进入wait状态

            // 计算了公钥并且返回给目标
            send_header->state = 1;
            send_header->length = put_len;

            // 完成数据组成，发送数据
            // 头文件的长度
            return send_header->length + HEADER_LEN;

            break;
        }
        case 2: {
            // 发送用户需要的信息串结构，按照标准写入buffer之中
            int put_len = compute_and_store_public_key(thread_send_buffer, DATA_LEN);
        }
        case 3: {
            // 用户发来的信息串序列，这是最基本的内容
            // 接收到用户信息序列，需要进行合理解析
            // 暂时存起来即可，每个线程对应一个独立用户

            // 这里的logic好麻烦好复杂！果然服务器非常难写

        }
        case 4: {
            // 用户请求计算签名，也就是论文中的sigma_c
        }
        default: {
            // 输入不合理，表示失败了
            printf("invalud document\n");
            now_state = -1;
        }
    }
    // 上文send完之后，将state归零or归为-1
    now_state = -1;

    // 不是0便是-1，这里明显有不合理的内容
    

    return 0;

}




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