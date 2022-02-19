#include "net_api.h"
#include "stdint_p.h"


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

    tmp_header = (struct protocol_header*) buf_recv;
    data_point = (char*)(buf_recv + HEADER_LEN);

    uint16_t_p data_region_len = tmp_header->length;
    
    struct public_key_IDP* tmp_pk_IDP = pk_IDP_from_bytes(data_point);

    printf("get the pk IDP\n");
    // 直接返回生成的公钥即可
    return tmp_pk_IDP;
}