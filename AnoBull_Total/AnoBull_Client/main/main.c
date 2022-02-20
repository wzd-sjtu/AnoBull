#include "main.h"
#include "stdlib.h"
#include "stdio.h"
#include "string.h"

#include "net_api.h"
#include "all_def.h"

#include "Elliptic_Curve.h"
#include "basic_algorithm.h"

int main() {

    printf("client start!\n");

    // how to write the code here? tmply unknown.

    // 首先要连接服务器,现在先暂时写死，后面再做修改

    // 全部使用协议封装，send和recv的解析需要全部封装

    int sockfd;    /* files descriptors */
    char buf_recv[MAX_LINE_BUFFER] = {0};    /* buf will store received text */
    char buf_send[MAX_LINE_BUFFER] = {0};

    sockfd = connect_IDP_server();

    // printf("connect successfully!\n");
    
    struct public_key_IDP* tmp_pk_IDP = ask_pk_IDP(sockfd, buf_recv, buf_send);

    // 继续获取对应的information
    struct list* user_info_infra = ask_user_info_infra(sockfd, buf_recv, buf_send);
    if(user_info_infra == NULL) {
        printf("get the none list!");
    }
    struct list_node* tmp = user_info_infra->vir_head->next;

    
    while(tmp != user_info_infra->vir_tail) {
        printf("val name is %s\n", (char*)tmp->val1);
        printf("description name is %s\n", (char*)tmp->val3);
        tmp = tmp->next;
    }

    // 下面可以对内容进行填入了！
    // 收到信息后，需要填充有关的内容？

    char input_buffer[1024] = {0};
    // 一个void函数，获取用户输入输出缓冲区
    fill_up_user_info(input_buffer, user_info_infra, 1024);

    send_user_info_to_IDP(sockfd, buf_recv, buf_send, user_info_infra);

    close(sockfd);

    while(1) {

    };
    return 0;
}