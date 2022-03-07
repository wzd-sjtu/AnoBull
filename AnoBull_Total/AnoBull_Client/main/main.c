#include "main.h"
#include "stdlib.h"
#include "stdio.h"
#include "string.h"

#include "net_config.h"
#include "net_api.h"
#include "all_def.h"

#include "Elliptic_Curve.h"
#include "basic_algorithm.h"

#include "test.h"

int main() {

    printf("[INFO] client start!\n");

    // how to write the code here? tmply unknown.

    // 首先要连接服务器,现在先暂时写死，后面再做修改

    // 全部使用协议封装，send和recv的解析需要全部封装

    int sockfd;    /* files descriptors */
    char buf_recv[MAX_LINE_BUFFER] = {0};    /* buf will store received text */
    char buf_send[MAX_LINE_BUFFER] = {0};

    sockfd = connect_IDP_server();
    printf("[INFO] client ip is %s\n", USER_IP);
    printf("[INFO] server ip is %s\n", SERVER_IP);
    printf("[INFO] connect server successfully!\n");
    
    struct public_key_IDP* tmp_pk_IDP = ask_pk_IDP(sockfd, buf_recv, buf_send);

    // 继续获取对应的information
    struct list* user_info_infra = ask_user_info_infra(sockfd, buf_recv, buf_send);
    if(user_info_infra == NULL) {
        printf("get the none list!");
    }
    struct list_node* tmp = user_info_infra->vir_head->next;

    
    while(tmp != user_info_infra->vir_tail) {
        // printf("val name is %s\n", (char*)tmp->val1);
        // printf("description name is %s\n", (char*)tmp->val3);
        tmp = tmp->next;
    }

    // 下面可以对内容进行填入了！
    // 收到信息后，需要填充有关的内容？

    char input_buffer[1024] = {0};
    // 一个void函数，获取用户输入输出缓冲区

    // 键盘输入api
    // fill_up_user_info(input_buffer, user_info_infra, 1024);

    // 固定输入api
    fill_up_user_info_automatic(input_buffer, user_info_infra, 1024);

    send_user_info_to_IDP(sockfd, buf_recv, buf_send, user_info_infra);


    // 状态四：请求计算签名 sigma_c
    struct sigma_c* res_sigma_c = ask_compute_sigma_c(sockfd, buf_recv, buf_send, tmp_pk_IDP);
    

    // printf("user info length is %d\n", user_info_infra->list_num);
    // printf("pk_IDP's length is %d\n", tmp_pk_IDP->total_num_of_h_i);


    // 本地计算sigma，作为重要的匿名凭证
    // selector_vector的维度是从0-(N)，一共有N+1的维度
    // 这个设计让人很难受
    char* selector_vector = (char*)malloc(tmp_pk_IDP->total_num_of_h_i);
    for(int i=0; i<tmp_pk_IDP->total_num_of_h_i;i++) {
        selector_vector[i] = 0;
    }
    // 这里的logic很奇怪。。
    // 在测试时，一定要记得，把selector_vector[0]标记为1，表示想要隐藏它
    selector_vector[0] = 1;
    selector_vector[2] = 1;
    selector_vector[3] = 1;

    // struct sigma* compute_sigma(struct sigma_c* signature_c, struct public_key_IDP* pk_IDP, \
       element_t* m_vector, char* select_vector);

    // 惊讶！这里居然没有生成m_vector的函数，最好再包装一下？？

    // element_t* convert_info_to_vector(struct list* user_info_list_specific, struct public_key_IDP* pk_IDP);

    // 已经完成了最基本的copy了，裂开！
    element_t* m_vector = convert_info_to_vector(user_info_infra, tmp_pk_IDP);

    // 不妨直接把m_vector给映射过去
    struct sigma* res_sigma = compute_sigma(res_sigma_c, tmp_pk_IDP, m_vector, selector_vector);

    // 下面对计算得到的sigma做一个检验

    // 检验服务器生成的初始匿名凭证
    verify_sigma_c_equation_1(res_sigma_c, tmp_pk_IDP);
    // 检验自己计算生成的匿名凭证
    

    // 不妨设计状态5，作为RP最终的身份验证环节吧
    // 实际上最好把这个信息传送过去，从而降低整个程序运行的开销

    // m_vector是否要发送过去？将m_vector存储为对应的链表即可，对的了
    // 居然directly裂开了，这里有非常深层次的bug，gg
    RP_verify(res_sigma, m_vector, selector_vector, tmp_pk_IDP);


    int store_length = store_service_info(buf_send, res_sigma, m_vector, selector_vector, tmp_pk_IDP);

    // 正式开始请求服务
    // 居然发送失败？
    ask_service(sockfd, buf_recv, buf_send, store_length);


    close(sockfd);
    // 这里是已经完成了所有information的获取和获得了

    while(1) {

    };
    return 0;
}
