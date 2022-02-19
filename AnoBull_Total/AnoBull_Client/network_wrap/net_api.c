#include "net_api.h"
#include "stdint_p.h"
#include "all_def.h"

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
    printf("recv num is %d\n", num);

    struct protocol_header* recv_header = (struct protocol_header*) buf_recv;
    char* recv_data = (char*)(buf_recv + HEADER_LEN);

    // uint16_t_p data_region_len = tmp_header->length;
    struct public_key_IDP* tmp_pk_IDP = NULL;
    if(recv_header->state == 1) {

        // so why there is a problem?
        tmp_pk_IDP = pk_IDP_from_bytes(recv_data);
        printf("get the pk IDP\n");
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
    printf("recv num is %d\n", num);

    struct protocol_header* recv_header = (struct protocol_header*) buf_recv;
    char* recv_data = (char*)(buf_recv + HEADER_LEN);

    // uint16_t_p data_region_len = tmp_header->length;
    struct list* res_list = NULL;
    if(tmp_header->state == 2) {

        // so why there is a problem?
        res_list = get_user_info_list(recv_data, recv_header->length);
        printf("get the user info list\n");
    }
    // 直接返回生成的公钥即可
    return res_list;
}
