#ifndef __IDP_INIT_H
#define __IDP_INIT_H
#include "/usr/local/include/pbc/pbc.h"
#include "/usr/local/include/pbc/pbc_test.h"
#include "stdio.h"
#include "stdlib.h"
#include <string.h>
#include <openssl/sha.h>

// 公钥of IDP
// to some fixed space yes!
struct public_key_IDP {
    // G2
    element_t omega;
    // 为了兼容，可以暂时留着它
    // 此时在重构，可以去掉它
    // struct h_i_node* virtual_head;
    // 所有的h_i均来自群G1
    // G1
    element_t* h_vector;

    int total_num_of_h_i;
    pairing_t* pair;
    // G1
    element_t g1;
    // G2
    element_t g2;
};

struct secret_key_IDP {
    // Z_p
    element_t gamma;
};

struct sigma_c {
    // Z_p
    element_t x;
    element_t s;
    // G_1
    element_t A;

    // G1  mid_res
    // h_0 h_1^m_i 连乘
    element_t middle_res;
};


pairing_t* init_space(char* curve_name);
struct secret_key_IDP* init_IDP_secret_key(pairing_t* pairing);
struct public_key_IDP* init_IDP_public_key(pairing_t* pairing, int N, struct secret_key_IDP* sk_IDP);


// IDP获得用户信息，进行解码
int is_hidden(char* select_vector, int loc);
// void hash_SHA256(unsigned char* data_buffer, int length, unsigned char result[]);
struct sigma_c* compute_sigma_c(element_t* m_vector, struct public_key_IDP* pk_IDP, \
 struct secret_key_IDP* sk_IDP);


#endif

// 这是为以后的处理打下良好的基础的了哦