#include "server_api.h"

// 重复听的次数
#define LISTENQ 10
#define HEADER_LEN 8
#define DATA_LEN 3064

// 公钥+私钥设置为全局变量
#include "global.h"
#include "protocol_structure.h"
#include "stdint_p.h"
#include "all_def.h"
#include "string.h"
// 这里涉及到了具体的数据库存储方式
#include "sqlite3_use.h"

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

    printf("[INFO] this is thread %d\n", clifd);

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

    // 5表示客户请求服务，发送来用户信息序列（如果不想暴露，只放出最基本的，别的使用' '一个空格表示无效，selector_vector需要在服务器端自己构建）
    // 收到  （1）用户自动生成的sigma_j （2）用户发来的信息串  主键是用户的sigma_j，并且设置发送过来的次数，这个次数是需要不断更新的
    // 暂时就使用这种逻辑来统计工作量算了，需要补一个int类型

    int length = 0;

    // printf("go into while\n");

    // 这个指针是需要大规模修改的了
    
    struct list* user_main_list = NULL;
    struct list** para_transmit = &user_main_list;

    while(1) {
        // 阻塞了网络，需要重新载入
        // 并不明白如何进行网络编程
        // 需要进行结构体的转换

        // 具体过程就是不断recv再不断send的过程
        // 这个是多线程里面最核心的内容

        printf("[START] begin recv:\n");
        length = recv(clifd, thread_recv_buffer, MAX_LINE_BUFFER_THREAD, 0);
        printf("[END] receive length is %d\n", length);
        // 阻塞读入长度为0，出现了问题
        if(length <= 0) {
            printf("[ERROR] read failed!\n");
            return;
        }
        

        // 一旦读取到buffer，直接进入process_recv函数
        // 收到消息总要返回一些东西
        printf("[START] begin compute the send thing!\n");
        length = process_recv(thread_recv_buffer, thread_send_buffer, length, para_transmit);
        printf("[END] send length is %d\n", length);

        // (num=send(sockfd,buf,HEADER_LEN + tmp_header->length, 0)==-1)
        // length 即为最终的缓冲区长度
        length = send(clifd, thread_send_buffer, length, 0);

        if(length == -1) {
            printf("[ERROR] send failed!\n");
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

int store_user_info_infra(char* send_buffer, int data_len_limit) {
    // 这里涉及到配置信息config
    // 这个参数貌似没有传递下来emm
    struct list* user_info_fra_list = all_config->user_info_list;

    // 取出链表
    // 遍历存入缓冲区
    struct list_node* head = user_info_fra_list->vir_head->next;
    struct list_node* tail = user_info_fra_list->vir_tail;

    int total_len = 0;
    int loc_i = 0;

    char* name = NULL;
    char* value = NULL;
    char* buf_tmp = send_buffer;


    while(head != tail) {
        // 将信息填入缓冲区
        // 由于strcpy缺陷，选择手动进行
        
        name = (char*)head->val1;
        value = (char*)head->val2;

        // printf("name and value is %s and %s\n", name, value);

        loc_i = 0;
        while(name[loc_i] != '\0') {
            *buf_tmp = name[loc_i];
            buf_tmp++;
            total_len++;
            loc_i++;
        }
        total_len++;
        *buf_tmp = '=';
        buf_tmp++;

        loc_i = 0;
        while(value[loc_i] != '\0') {
            *buf_tmp = value[loc_i];
            buf_tmp++;
            total_len++;
            loc_i++;
        }

        total_len++;
        // use the blank to split the data here
        *buf_tmp = '\0';
        buf_tmp++;

        head = head->next;
    }

    // 这里没有进行缓冲区保护，将来有可能出现溢出问题？
    // 暂时先写一个最简单的手段吧
    return total_len;
}

// 提前留下的接口，专门用于持久化存储的函数
void store_sigma_c(char* sigma_c_buffer, int length, struct list* user_info_list) {

    struct list_node* tmp_list_node = user_info_list->vir_head->next;
    char* name_select = NULL;
    while(tmp_list_node != user_info_list->vir_tail) {
        if(strcmp(tmp_list_node->val1, "name") == 0) {
            name_select = tmp_list_node->val2;
            break;
        }
        tmp_list_node = tmp_list_node->next;
    }
    // 每次store都需要存储最基本的数据库知识啦！
    // 这个数据库打开关闭的开销是否需要考虑呢？不明白
    // store_sigma_c(will_send_sigma_c, user_info_list_specific);

    // 需要构建一个表，外加一个对应的sigma_c

    return;
}
struct list* recv_user_info_list(char* recv_data, struct protocol_header* recv_header) {

    // 这里是把需要填充的信息直接填写进去
    struct list* tmp_list = init_list();

    int loc = 0;
    char data_buffer[1024];
    int data_length = (int)recv_header->length;
    // printf("recv data is %s\n", recv_data);
    while(loc < data_length) {
        char* name = NULL;
        char* description = NULL;

        int i = 0;
        while(loc < data_length && recv_data[loc] != '=') {
            // 第一个name的存储
            data_buffer[i] = recv_data[loc];
            i++;
            loc++;
        }
        data_buffer[i] = '\0';
        name = (char*)malloc(i); // 大小做改变
        strcpy(name, data_buffer);

        // printf("name is %s\n", name);

        i = 0;
        loc++;
        while(loc < data_length && recv_data[loc] != '\0') {
            // 第二个value的存储
            data_buffer[i] = recv_data[loc];
            i++;
            loc++;
        }
        // 用户端填写完成后，也需要再次输入进去
        data_buffer[i] = '\0';
        description = (char*)malloc(i);
        strcpy(description, data_buffer);
        // printf("description is %s\n", description);

        // jump the blank
        loc++;

        // 确实有且仅有位置1和位置2
        push_front(name, description, NULL, tmp_list);
    }

    return tmp_list;
}

// 提前留下的接口，专门用于数据的持久化处理
int store_user_info(struct list* user_info_list) {
    // 这里和上文的另一个函数会非常地相似

    // 这里本意是存储用户信息，例如存储到数据库或者别的location里面
    // 还可以选择给用户计算一个唯一的凭证标识

    // 现在就暂时把此处的代码给空置
    // int insert_user_info_by_list(struct list* user_info_list)

    // 这个函数是dao数据持久化层中使用的，位置有点乱啦
    insert_user_info_by_list(user_info_list);

    return 0;
}


int process_recv(char* thread_recv_buffer, char* thread_send_buffer, int recv_length, void** para_transmit) {
    // 指针强制类型转换
    struct protocol_header* recv_header = (struct protocol_header*)thread_recv_buffer;
    struct protocol_header* send_header = (struct protocol_header*)thread_send_buffer;

    // 发送头header清零
    memset(send_header, 0, sizeof(struct protocol_header));

    // header len已经固定为8bytes，不需要再次修改了
    char* recv_buffer = (char*)(thread_recv_buffer + HEADER_LEN);
    char* send_buffer = (char*)(thread_send_buffer + HEADER_LEN);
    // 关键信息提取
    uint8_t_p data_len = recv_header->length;
    uint8_t_p now_state = recv_header->state;


    // 用户信息list
    // 每一个线程都拥有自己独立的list，并且这个list不需要继续向上传递

    struct list* user_info_list_specific = NULL;

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
            // 用户请求信息串结构
            // 存储方法：
            // key:value key:value  , 中间以空格分离

            // DATA_LEN是长度上限
            // just get the different code here
            int put_len = store_user_info_infra(send_buffer, DATA_LEN);

            send_header->state = 2;
            send_header->length = put_len;

            return send_header->length + HEADER_LEN;
        }
        case 3: {
            // 用户发来的信息串序列，这是最基本的内容
            // 接收到用户信息序列，需要进行合理解析
            // 暂时存起来即可，每个线程对应一个独立用户

            // 这里的logic好麻烦好复杂！果然服务器非常难写
            
            // logic总是非常简单的了

            // 一个存header，一个存buffer

            // 这里的api是要自己独立使用的，不需要做额外的工作

            // 上文已经完成定义的list，在这里使用函数填充
            user_info_list_specific = recv_user_info_list(recv_buffer, recv_header);










        // 及其危险的操作
        // 为了让程序运行，加了一个无锁的全局变量，并且会被不断修改
        // pub_list = user_info_list_specific;
        // 二重指针参数原地修改
        *(struct list**)para_transmit = user_info_list_specific;










            // traverse_show_list(user_info_list_specific);
            // 再把list存入send_buffer里面，供后面填充

            // 将信息串序列存入数据库，信息持久化
            // 这个持久化是必备的，缺一不可，可以补一个全局资源池来存储，从而支持并发
            // 可以暂时设计层带锁的全局位图存储
            // 最好的法子还是存入数据库，我真是吐了。。
            
            int put_len = store_user_info(user_info_list_specific);
            
            send_header->state = 3;
            
            strcpy(send_buffer, "Server has receive and store your information!");
            // 自带'\0'，可以使用strcpy函数
            send_header->length = strlen(send_buffer);
            return send_header->length + HEADER_LEN;

        }
        case 4: {
            // 用户请求计算签名，也就是论文中的sigma_c

            // 这个函数是非常easy
            // 这里是服务器的核心logic，请求对应的匿名凭证签名
            // 收发信息已经封装，需要写的只有读写缓冲区
            recv_buffer[recv_header->length] = '\0';
            printf("[INFO] client request is:%s\n", recv_buffer);
            
            // N会在pk_IDP内完成设置

            // 这里的无锁全局变量很危险，最好存入数据库
            // traverse_show_list(pub_list);

            struct list* user_info_list_specific = *(struct list**)para_transmit;
            // printf("[DEBUG DEBUG] user info dimention is %d\n", user_info_list_specific->list_num);
            // 将用户信息存储进入对应的表格之中即可
            element_t* m_vector = convert_info_to_vector(user_info_list_specific, pk_IDP);
            
            // pub_list
            struct sigma_c* will_send_sigma_c = compute_sigma_c(m_vector, pk_IDP, sk_IDP);
            

            // 填入缓冲区
            int put_len = sigma_c_to_bytes(will_send_sigma_c, send_buffer, DATA_LEN);


            // 进行持久化存储
            // 存储这个sigma_c的意义是什么
            // here的userinfo还是总是需要的
            store_sigma_c(send_buffer, put_len, user_info_list_specific);

            // printf("put_len:%d\n", put_len);
            // 下面这个新功能需要先测试再进行添加处理了！
            // struct sigma_c* gg = sigma_c_from_bytes()
            // 将目标转化为bytes
            send_header->state = 4;
            send_header->length = put_len;
            
            // 这里又是新的api，信息存储api又来了
            return send_header->length + HEADER_LEN;
        }
        case 5: {
            // 这个case 5没有进行合理处理

            // recv_header recv_buffer
            // length is tmply unknown
            // pk_IDP is a global variable.
            // 这个length是暂时未知的。。

            // 初始定义二重指针时，指向NULL
            // 自己指向NULL？明显不对了
            char* no_use = "no";
            char** m_vector_point = &no_use;
            
            // 计算sigma时就已经出现问题了，貌似并非free的问题
            // printf("[DEBUG DEBUG] begin get the sigma\n");
            struct sigma* recvived_signature = sigma_from_bytes(recv_buffer, 0, pk_IDP, m_vector_point);
            // printf("[DEBUG DEBUG] end get the sigma\n");

            // 真的让人头疼。。
            // m_vector_point 已经被自动重定向了
            // 成功搞到了m_vector
            // printf("m_vector_info is %s \n", *m_vector_point);
            // element_t* m_vector = get_the_m_vector(*m_vector_point, pk_IDP);
            // char* selector_vector = get_selector_vector(m_vector, pk_IDP);
            struct m_vector_and_selector_struct* added_struct = get_the_m_vector_and_selector_vector(*m_vector_point, pk_IDP);
            strcpy(send_buffer, "[INFO] Server has receive your basic signature and m_vector!");
            // 至此完成结果获取

            element_t* m_vector = added_struct->m_vector;
            char* selector_vector = added_struct->selector_vector;

            // 下面正式进行验证
            // 在进行RP_verify时，需要生成暂时的中间变量，记得把中间变量保存下来哦
            element_t* R2_will_cache = RP_verify(recvived_signature, m_vector, selector_vector, pk_IDP);
            
            // 下面再进行数据的持久化
            // 这让人暂时是非常无语ing的啦

            // 进行数据持久化存储
            // 每一个数据结构都应当有自己的接口，从而尽可能来提升效率
            struct sigma_store* sigma_store_cache = init_sigma_store(recvived_signature, R2_will_cache, pk_IDP);

            // 完成内容初始化，下面转换为数据库的存储方式
            // 存储到对应的数据库里面，从而提升效率
            // 当上面这一步完成后，就可以进入正式的程序测试阶段了
            
            

            send_header->state = 5;
            send_header->length = strlen(send_buffer) + 1;


            return send_header->length + HEADER_LEN;

        }
        default: {
            // 输入不合理，表示失败了
            printf("invalud document\n");
            now_state = -1;

            // 对于所有生成的information，进行对应的处理即可完成
            
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
    printf("[INFO] listening on %d\n",port);
	
    // 网络部分的架构不应该放在这一部分实现，位置有误
    // 正式进入while循环服务器
	for(;;) {
        // printf("begin accept!\n");
		connfd=accept(sockfd,(struct sockaddr *)&cli_addr, &sin_size);
        // printf("end accept!\n");
		if(connfd<0) {
			printf("accept error.\n");
			continue;
		}
		else {
			printf("[INFO] generate the new socket connfd: %d \n", connfd);
		}
        // int thpool_add_work(threadpool, void (*function_p)(void*), void* arg_p);
        thpool_add_work(IDP_thread_pool, Thread_function, (void*)connfd);
        // thpool就是线程池
	}
}