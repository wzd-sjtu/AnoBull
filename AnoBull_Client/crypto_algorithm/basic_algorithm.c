#include "/usr/local/include/pbc/pbc.h"
#include "/usr/local/include/pbc/pbc_test.h"
#include "stdio.h"
#include "stdlib.h"
#include <string.h>
#include <openssl/sha.h>
#include "all_def.h"
#include "basic_algorithm.h"
#include "Elliptic_Curve.h"

// 均是在运行中生成，堆空间应该是很大才对
pairing_t* init_space(char* curve_name) {
    if(strcmp(curve_name, "D224") == 0) {
        // printf("this is init space!!\n\n");
        size_t count = strlen(D224_param);
        pairing_t* tmp = (pairing_t*)malloc(sizeof(pairing_t));
        pairing_init_set_buf(*tmp, D224_param, count);
        // element_t g1;
        // printf("init pair successfully!\n");
        // 传递出去的变量，应当是不会消失才对的
        return tmp;
    }
    return NULL;
}

int is_hidden(char* select_vector, int loc) {
     if((select_vector[loc]&0x01)==1) {
         return 1;
     }
     else return 0;
}
