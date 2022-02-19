#include "main.h"
#include "stdlib.h"
#include "stdio.h"
#include "string.h"

#include "net_api.h"
#include "all_def.h"

int main() {

    printf("client start!\n");

    // how to write the code here? tmply unknown.

    // 首先要连接服务器,现在先暂时写死，后面再做修改

    // 全部使用协议封装，send和recv的解析需要全部封装

    int sockfd;    /* files descriptors */
    char buf_recv[MAX_LINE_BUFFER];    /* buf will store received text */
    char buf_send[MAX_LINE_BUFFER];

    sockfd = connect_IDP_server();

    printf("connect successfully!\n");
    
    struct public_key_IDP* tmp_pk_IDP = ask_pk_IDP(sockfd, buf_recv, buf_send);

    close(sockfd);

    while(1) {

    };
    return 0;
}