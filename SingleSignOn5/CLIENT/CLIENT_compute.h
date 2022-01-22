#ifndef __CLIENT_CLIENT_CONPUTE_H
#define __CLIENT_CLIENT_CONPUTE_H

#include "IDP_init.h"
// 保存关键的数据结构
struct sigma {
    // G1
    element_t A_plus;
    // G1
    element_t A_ba;

    // G1
    element_t d;

    // R1 and R2 also in G1
    // c还是取到Z_p中比较合理？
    element_t c;
    
    // Z_p
    element_t z_x;
    element_t z_r;
    element_t z_alpha;
    element_t z_beta;

    element_t* z_i_hidden;

    // 缓存起来，用于加速
    // 最好保存为全局变量？
    //////// 重要的中间变量，连乘上套了一个r次方 ////////
    // 此处不需要middle_res
    // element_t middle_res;
};

void hash_SHA256(unsigned char* data_buffer, int length, unsigned char result[]);
struct sigma* compute_sigma(struct sigma_c* signature_c, struct public_key_IDP* pk_IDP, \
    element_t* m_vector, char* select_vector);
#endif