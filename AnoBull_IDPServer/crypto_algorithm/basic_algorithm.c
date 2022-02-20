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
        size_t count = strlen(D224_param);
        pairing_t* tmp = (pairing_t*)malloc(sizeof(pairing_t));
        pairing_init_set_buf(*tmp, D224_param, count);
        return tmp;
    }
    return NULL;
}


struct secret_key_IDP* init_IDP_secret_key(pairing_t* pairing) {
    struct secret_key_IDP* tmp = (struct secret_key_IDP*)malloc(sizeof(struct secret_key_IDP));
    memset(tmp, 0, sizeof(struct secret_key_IDP));
    element_init_Zr(tmp->gamma, *pairing);
    // 生成随机私钥
    element_random(tmp->gamma);
    return tmp;
}
struct public_key_IDP* init_IDP_public_key(pairing_t* pairing, int N, struct secret_key_IDP* sk_IDP) {
    struct public_key_IDP* pk_IDP = (struct public_key_IDP*)malloc(sizeof(struct public_key_IDP));
    memset(pk_IDP, 0, sizeof(struct public_key_IDP));

    // 需要提前初始化
    element_init_G1(pk_IDP->g1, *pairing);
    element_init_G2(pk_IDP->g2, *pairing);
    element_init_G2(pk_IDP->omega, *pairing);
    
    // element of g1 and g2
    element_t g1;
    element_t g2;
    element_init_G1(g1, *pairing);
    element_init_G2(g2, *pairing);
    element_random(g1);
    element_random(g2);


    element_set(pk_IDP->g1, g1);
    element_set(pk_IDP->g2, g2);
    
    // 指针指向固定的一个元素
    pk_IDP->pair = pairing;

    // 数值赋值，为公钥做计算准备
    // element_t* gamma = &sk_IDP->gamma;
    // ==
    element_t omega;
    element_init_G2(omega, *pairing);
    element_pow_zn(omega, g2, sk_IDP->gamma);

    element_set(pk_IDP->omega, omega); // 内容赋值, pk_IDP->omega = omega;

    // total num calculate and compute
    pk_IDP->total_num_of_h_i = N;

    // h_i_node init
    // use h_vector to simplify the code
    pk_IDP->h_vector = (element_t*)malloc(N*sizeof(element_t));
    for(int i=0; i<N; i++) {
        element_init_G1(pk_IDP->h_vector[i], *pairing);
        element_random(pk_IDP->h_vector[i]);
    }

    element_clear(g1);
    element_clear(g2);
    element_clear(omega);

    return pk_IDP;
}
// 查看此index是否在被选择之列表
int is_hidden(char* select_vector, int loc) {
     if((select_vector[loc]&0x01)==1) {
         return 1;
     }
     else return 0;
}

/*
void hash_SHA256(unsigned char* data_buffer, int length, unsigned char result[]) {
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, data_buffer, length);

    SHA256_Final(result, &sha256_ctx);
    return;
}
*/
struct sigma_c* compute_sigma_c(element_t* m_vector, struct public_key_IDP* pk_IDP, \
 struct secret_key_IDP* sk_IDP) {
    // 计算初始颁发的匿名凭证
    struct sigma_c* signature_c = (struct sigma_c*)malloc(sizeof(struct sigma_c));
    memset(signature_c, 0, sizeof(struct sigma_c));

    element_init_Zr(signature_c->x, *pk_IDP->pair);
    element_random(signature_c->x);
    element_init_Zr(signature_c->s, *pk_IDP->pair);
    element_random(signature_c->s);
    element_init_G1(signature_c->A, *pk_IDP->pair);

    // 计算A
    element_t res;
    element_init_G1(res, *pk_IDP->pair);

    element_t parcel;
    element_init_G1(parcel, *pk_IDP->pair);

    element_pow_zn(parcel, pk_IDP->h_vector[0], signature_c->s);
    element_set(res, parcel);

    int N = pk_IDP->total_num_of_h_i;
    for(int i=1; i<N; i++) {
        element_pow_zn(parcel, pk_IDP->h_vector[i], m_vector[i]);
        element_mul(res, res, parcel);
    }

    element_mul(res, res, pk_IDP->g1);

    //////// 此时计算得到了重要的中间连乘，可以作为有效的中间变量 ////////
    element_init_G1(signature_c->middle_res, *pk_IDP->pair);
    element_set(signature_c->middle_res, res);


    // 处理计算A需要的指数
    element_t exponent_res;
    element_init_Zr(exponent_res, *pk_IDP->pair);
    element_add(exponent_res, sk_IDP->gamma, signature_c->x);

    element_t one_expo;
    element_init_Zr(one_expo, *pk_IDP->pair);
    element_set1(one_expo); // 做经典的除法

    // void element_div(element_t n, element_t a, element_t b)
    element_div(exponent_res, one_expo, exponent_res);

    // 最后再做指数运算
    element_pow_zn(res, res, exponent_res);

    element_set(signature_c->A, res);

    element_clear(res);
    element_clear(parcel);
    element_clear(exponent_res);
    element_clear(one_expo);

    return signature_c;
}

// 将list转换为对应的vector
element_t* convert_info_to_vector(struct list* user_info_list_specific, struct public_key_IDP* pk_IDP) {
    // element_init_Zr

    // 信息序列的维度
    int N = pk_IDP->total_num_of_h_i;
    element_t* m_vector = malloc(N*sizeof(element_t));
    for(int i=0; i<N; i++) {
        element_init_Zr(m_vector, *pk_IDP->pair);
    }

    // 进行维度映射
    struct list_node* tmp_node = user_info_list_specific->vir_head->next;
    for(int i=0; i<N; i++) {
        // 进行简单的映射
        // void element_from_hash(element_t e, void *data, int len)
        element_from_hash(m_vector[i], (char*)tmp_node->val2, strlen(tmp_node->val2));
    }
    // 完成内容的拼写，为后文的传送打下一定的基础
    return m_vector;
}