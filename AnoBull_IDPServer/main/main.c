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
#include "basic_algorithm.h"
#include "server_api.h"

#include "structure_to_bytes.h"

// 需要使用的算法

int main() {
    // 整个程序的主架构
    // socket需要参考csapp做对应的改编
    // 从而提升程序的运行效率

    // 编码过程中的测试环节
    // test_all();

    // 配置信息初始化，首先采取手动输入的方式编写
    
    // struct config_structure* test_config_specific = init_test_config();

    
    // 下面是一些打印信息
    struct config_structure* test_config_specific = read_config_init();

    // 不会改动的全局变量，可以并行读取
    all_config = test_config_specific;
    // 打印所选择的椭圆曲线
    // printf(test_config_specific->Elliptic_Curve_Selection);
    // printf(test_config_specific->Elliptic_Curve_Selection);printf("\n");
    // printf(test_config_specific->IP_address);printf("\n");

    // printf("length of curve is %d\n", strlen(test_config_specific->Elliptic_Curve_Selection));

    // printf("num is %d\n", test_config_specific->port_num);
    // printf("max thread is %d\n", test_config_specific->max_connect_thread_number_num);

    // whether it is successfully? this is always unknown...
    printf("config set init successfully!\n");

    // pairing_t* init_space(char* curve_name);
    // struct secret_key_IDP* init_IDP_secret_key(pairing_t* pairing);
    // struct public_key_IDP* init_IDP_public_key(pairing_t* pairing, int N, struct secret_key_IDP* sk_IDP);
    
    // complete the init of the group? what is this thing?
    // pairing_t* pair_choice = init_space(test_config_specific->Elliptic_Curve_Selection);
    

    pairing_t* pair_choice =NULL;
    pair_choice = init_space("D224");
    if(pair_choice == NULL) {
        printf("pair you have chosen is not existing.");
        return 0;
    }

    
    sk_IDP = init_IDP_secret_key(pair_choice);
    
    int info_dimention = test_config_specific->user_info_list->list_num;
    printf("info dimention is %d\n", info_dimention);
    pk_IDP = init_IDP_public_key(pair_choice, info_dimention, sk_IDP);
    printf("Gene public_key and Gene secret_key successfully!\n");
    
    /*
    char test_char[4098] = {0};
    int lenlen = pk_IDP_to_bytes(test_char, 0);
    struct public_key_IDP* recover_pk_IDP = pk_IDP_from_bytes(test_char, 0);
    if(comapre_pk_IDP(recover_pk_IDP) == 1) {
        printf("yes yes yes!\n");
    }
    */

    // 初始化thread_pool 线程池
    // 线程池数据结构
    // typedef struct thpool_* threadpool;
    
    // 这里的全局变量设计。。  确实是需要有一个全局变量的
    
    // 这里有个小问题，用的是uint转换为int，可能会存在溢出？
    threadpool IDP_thread_pool = thpool_init((int)test_config_specific->max_connect_thread_number_num);
    printf("thread pool completed!\n");
    // 线程池API
    // int thpool_add_work(threadpool, void (*function_p)(void*), void* arg_p);
    // void thpool_wait(threadpool);
    // int thpool_num_threads_working(threadpool);
    // 很显然，线程池要远比自定义的多线程好用


    // 正式进入服务器，线程池服务器
    printf("初始化完成，进入服务器\n");
    // 确实进入了服务器，但还是不明白这里的logic是什么情况
    start_main_server(test_config_specific, IDP_thread_pool);


    printf("some error happened!\n");
    while(1) {
        // printf("some error happened!\n");
    }
    return 0;
}