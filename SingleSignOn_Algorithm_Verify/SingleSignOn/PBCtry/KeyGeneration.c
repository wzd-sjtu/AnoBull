#include "/usr/local/include/pbc/pbc.h"
#include "/usr/local/include/pbc/pbc_test.h"
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include "GlobalPara.h"

// 下面需要定义这里要使用的API

// 外界来的API
// 关于安全参数如何取得？暂时是不明白的了

extern D224_param[1347];

// how to construct the basic data structure?
// need to carefully design

void init_space(char* curve_name, pairing_t* pairing) {
    if(strcmp(curve_name, "D224")) {
        size_t count = strlen(D224_param);
        // printf("%d\n", count);
        // 经测试，d224椭圆曲线参数数组大小为1346，故将大小初始化为1347byte，即为char param[1347]
        pairing_init_set_buf(*pairing, D224_param, count);
    }
}

// think clearly about the complete system
void init_idp(element_t* gamma_s, element_t* g_2, element_t* omega \
            pairing_t* pairing) {
    // 是否需要耦合？还是开发解耦合版本？暂时是不明白的了

}