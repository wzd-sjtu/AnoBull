#include "net_api.h"
#include "stdint_p.h"
#include "all_def.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

// 返回连接后形成的套接字
int connect_IDP_server() {
    // 这里仅仅进行

    int sockfd;    /* files descriptors */

    struct sockaddr_in server;

 
    if((sockfd=socket(AF_INET,SOCK_STREAM, 0))==-1)
    {
        printf("socket() error\n");
        // -1 represents it's unreasonable thing
        return -1;
    }
    // set the space to zero
    bzero(&server,sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(SERVER_PORT);
    server.sin_addr.s_addr = inet_addr(SERVER_IP);

    if(connect(sockfd, (struct sockaddr *)&server, sizeof(server))==-1)
    {
        printf("connect() error\n");
        return -1;
    }

    return sockfd;
}


struct public_key_IDP* ask_pk_IDP(int sockfd, char* buf_recv, char* buf_send) {

    // 首先目标是send再recv，这个顺序要考虑consider清楚
    struct protocol_header* tmp_header = (struct protocol_header*) buf_send;
    memset(tmp_header, 0, sizeof(struct protocol_header));
    // 请求公钥
    tmp_header->sig_pro = 1;
    tmp_header->state = 1;
    
    char* data_point = (char*)(buf_send + HEADER_LEN);
    strcpy(data_point, "Hello Server! I am Client! and I want pk_IDP!");
    tmp_header->length = strlen(data_point); // 存入对应的信息即可得部分结果

    int num = send(sockfd, buf_send, HEADER_LEN + tmp_header->length, 0);

    if(num == -1) {
        printf("send failed!\n");
        return NULL;
    }

    // 对于收到的数据，直接解析数据区即可

    num = recv(sockfd, buf_recv, MAX_LINE_BUFFER, 0);
    printf("[SUCCESS] recv num is %d\n", num);

    struct protocol_header* recv_header = (struct protocol_header*) buf_recv;
    char* recv_data = (char*)(buf_recv + HEADER_LEN);

    // uint16_t_p data_region_len = tmp_header->length;
    struct public_key_IDP* tmp_pk_IDP = NULL;
    if(recv_header->state == 1) {

        // so why there is a problem?
        tmp_pk_IDP = pk_IDP_from_bytes(recv_data);
        printf("[INFO] get the pk IDP\n");
    }
    // 直接返回生成的公钥即可
    return tmp_pk_IDP;
}

struct list* get_user_info_list(char* recv_data, uint16_t_p data_length) {
    struct list* tmp_list = init_list();

    int loc = 0;
    char data_buffer[1024];
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
        data_buffer[i] = '\0';
        description = (char*)malloc(i);
        strcpy(description, data_buffer);
        // printf("description is %s\n", description);

        // jump the blank
        loc++;

        push_front(name, NULL, description, tmp_list);
    }

    return tmp_list;
}

struct list* ask_user_info_infra(int sockfd, char* buf_recv, char* buf_send) {
    // 目前已经获得目标消息了
    // 首先目标是send再recv，这个顺序要考虑consider清楚
    struct protocol_header* tmp_header = (struct protocol_header*) buf_send;
    memset(tmp_header, 0, sizeof(struct protocol_header));
    // 请求公钥
    tmp_header->sig_pro = 2;
    tmp_header->state = 2;
    
    char* data_point = (char*)(buf_send + HEADER_LEN);
    strcpy(data_point, "Hello Server! I am Client! and I want user_info_infra!");
    tmp_header->length = strlen(data_point); // 存入对应的信息即可得部分结果

    int num = send(sockfd, buf_send, HEADER_LEN + tmp_header->length, 0);

    if(num == -1) {
        printf("send failed!\n");
        return NULL;
    }

    // 对于收到的数据，直接解析数据区即可

    num = recv(sockfd, buf_recv, MAX_LINE_BUFFER, 0);
    printf("[SUCCESS] recv num is %d\n", num);

    struct protocol_header* recv_header = (struct protocol_header*) buf_recv;
    char* recv_data = (char*)(buf_recv + HEADER_LEN);

    // uint16_t_p data_region_len = tmp_header->length;
    struct list* res_list = NULL;
    if(tmp_header->state == 2) {

        // so why there is a problem?
        res_list = get_user_info_list(recv_data, recv_header->length);
        printf("[INFO] get the user info list\n");
    }
    // 直接返回生成的公钥即可
    return res_list;
}

void fill_up_user_info(char* input_buffer, struct list* user_info_infra, int input_length_limit) {
    struct list_node* tmp_node = user_info_infra->vir_head->next;
    
    // 当然也可以从键盘读入
    // 也可以从配置文件读入
    // 也可以输入空，如果默认为空，那么可以加入一些别的信息
    while(tmp_node != user_info_infra->vir_tail) {
        
        printf("please type your %s(", (char*)tmp_node->val1);
        printf((char*)tmp_node->val3);
        printf(")::\n");

        // 这里会自带反斜杠零
        // 读取非换行符，不会有'\0'
        int in_len = scanf("%[^\n]", input_buffer);
        // 取掉多余的换行符
        getchar();

        // input_buffer[in_len] = '\0';
        printf("receive thing is %s\n", input_buffer);
        if(in_len == 0) {
            strcpy(input_buffer, "empty input");
        }
        // printf("receive data is %s\n", input_buffer);
        // printf("the length of buffer is %d", strlen(input_buffer));

        char* tmp_str = malloc(strlen(input_buffer) + 1);
        strcpy(tmp_str, input_buffer);

        tmp_node->val2 = tmp_str;

        // 至此完成内容的输入
        tmp_node = tmp_node->next;
    }

    return;
}

void fill_up_user_info_automatic(char* input_buffer, struct list* user_info_infra, int input_length_limit) {
    struct list_node* tmp_node = user_info_infra->vir_head->next;
    
    // 当然也可以从键盘读入
    // 也可以从配置文件读入
    // 也可以输入空，如果默认为空，那么可以加入一些别的信息
    while(tmp_node != user_info_infra->vir_tail) {
        
        char* tmp_str = "automatic input";

        // 局部变量会自动跳出对应的范围
        tmp_node->val2 = (char*)malloc(strlen(tmp_str) + 1);
        strcpy(tmp_node->val2, tmp_str);

        // 至此完成内容的输入
        tmp_node = tmp_node->next;
    }

    return;
}

int send_user_info_to_IDP(int sockfd, char* buf_recv, char* buf_send, struct list* user_info_fra_list) {

    // 取出链表
    // 遍历存入缓冲区

    struct protocol_header* tmp_header = (struct protocol_header*) buf_send;
    memset(tmp_header, 0, sizeof(struct protocol_header));
    // 请求公钥
    tmp_header->sig_pro = 3;
    tmp_header->state = 3;
    char* data_point = (char*)(buf_send + HEADER_LEN);


    struct list_node* head = user_info_fra_list->vir_head->next;
    struct list_node* tail = user_info_fra_list->vir_tail;

    int total_len = 0;
    int loc_i = 0;

    char* name = NULL;
    char* value = NULL;
    char* buf_tmp = data_point;


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
    tmp_header->length = total_len++;

    // 全部存入缓冲区，直接发送即可


    int num = send(sockfd, buf_send, HEADER_LEN + tmp_header->length, 0);

    if(num == -1) {
        printf("send failed!\n");
        return NULL;
    }

    // 对于收到的数据，直接解析数据区即可

    num = recv(sockfd, buf_recv, MAX_LINE_BUFFER, 0);
    printf("[SUCCESS] recv num is %d\n", num);

    struct protocol_header* recv_header = (struct protocol_header*) buf_recv;
    char* recv_data = (char*)(buf_recv + HEADER_LEN);
    recv_data[recv_header->length] = '\0';

    if(tmp_header->state == 3) {
        printf("[INFO] server reply:%s\n", recv_data);
    }

    // 返回值为1，表示发送成功，并且接收到服务器的回复
    return 1;
}



struct sigma_c* ask_compute_sigma_c(int sockfd, char* buf_recv, char* buf_send, struct public_key_IDP* tmp_pk_IDP) {
    // 目前已经获得目标消息了
    // 首先目标是send再recv，这个顺序要考虑consider清楚
    struct protocol_header* tmp_header = (struct protocol_header*) buf_send;
    memset(tmp_header, 0, sizeof(struct protocol_header));
    // 请求公钥
    tmp_header->sig_pro = 4;
    tmp_header->state = 4;
    
    char* data_point = (char*)(buf_send + HEADER_LEN);
    strcpy(data_point, "Hello Server! I am Client! and I want sigma_c which is the 匿名凭证!");
    tmp_header->length = strlen(data_point); // 存入对应的信息即可得部分结果

    int num = send(sockfd, buf_send, HEADER_LEN + tmp_header->length, 0);

    if(num == -1) {
        printf("send failed!\n");
        return NULL;
    }

    // 对于收到的数据，直接解析数据区即可

    num = recv(sockfd, buf_recv, MAX_LINE_BUFFER, 0);
    printf("[SUCCESS] recv num is %d\n", num);

    // m_0 与 m_1的地位是完全不同的
    struct protocol_header* recv_header = (struct protocol_header*) buf_recv;
    char* recv_data = (char*)(buf_recv + HEADER_LEN);

    // uint16_t_p data_region_len = tmp_header->length;
    struct sigma_c* res_sigma_c = NULL;
    if(tmp_header->state == 4) {

        // so why there is a problem?
        // struct sigma_c* sigma_c_from_bytes(char* data_buffer, int length, struct public_key_IDP* pk_IDP);
        // also 需要公钥！

        // 一个地方存公钥，一个地方存私钥，让人费解
        res_sigma_c = sigma_c_from_bytes(recv_data, recv_header->length, tmp_pk_IDP);
        printf("[INFO] successfully get the sigma_c!\n");
    }
    // 直接返回计算的签名即可
    return res_sigma_c;
}

// 将用户自定义签名+选择信息序列存入缓冲区
// 并且状态为5
int store_service_info(char* buf_send, struct sigma* signature, element_t* m_vector, char* select_vector, \
    struct public_key_IDP* pk_IDP) {

    // 首先目标是send再recv，这个顺序要考虑consider清楚
    struct protocol_header* tmp_header = (struct protocol_header*) buf_send;
    memset(tmp_header, 0, sizeof(struct protocol_header));
    // 请求服务，也就是状态5
    tmp_header->sig_pro = 5;
    tmp_header->state = 5;
    
    // HEADER_LEN是规定死的协议protocol
    char* data_point = (char*)(buf_send + HEADER_LEN);
    
    // 向data_point存入必要的信息即可

    // int sigma_to_bytes(struct sigma* will_send_sigma, char* data_buffer, int data_len_limit, struct public_key_IDP* pk_IDP);
    // 存入sigma
    int add_len = sigma_to_bytes(signature, data_point, DATA_LEN, pk_IDP);
    // printf("[DEBUG DEBUG] convert the sigma to bytes!\n");
    // 存入selector_vector
    add_len += filling_selected_m_vector_into_buffer(data_point + add_len, m_vector, select_vector, pk_IDP);

    tmp_header->length = add_len;

    //
    return add_len + HEADER_LEN;
}

// int RP_verify(struct sigma* signature, element_t* m_vector, char* select_vector, \
    struct public_key_IDP* pk_IDP);

int ask_service(int sockfd, char* buf_recv, char* buf_send, int send_len) {
    int num = send(sockfd, buf_send, send_len, 0);

    if(num == -1) {
        printf("send failed!\n");
        return NULL;
    }

    // 对于收到的数据，直接解析数据区即可

    num = recv(sockfd, buf_recv, MAX_LINE_BUFFER, 0);
    printf("[SUCCESS] recv num is %d\n", num);
    printf("[SUCCESS] recv info is %s\n", buf_recv + HEADER_LEN);

    // m_0 与 m_1的地位是完全不同的
    struct protocol_header* recv_header = (struct protocol_header*) buf_recv;
    char* recv_data = (char*)(buf_recv + HEADER_LEN);

    // 收到对应的消息即可了
    return num;
}