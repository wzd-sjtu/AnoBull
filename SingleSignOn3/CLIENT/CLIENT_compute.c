#include "CLIENT_compute.h"
#include "IDP_init.h"
#include "/usr/local/include/pbc/pbc.h"
#include "/usr/local/include/pbc/pbc_test.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

void hash_SHA256(unsigned char* data_buffer, int length, unsigned char result[]) {
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, data_buffer, length);

    SHA256_Final(result, &sha256_ctx);
    return;
}



struct sigma* compute_sigma(struct sigma_c* signature_c, struct public_key_IDP* pk_IDP, \
    element_t* m_vector, char* select_vector) {
    
    int N = pk_IDP->total_num_of_h_i;

    struct sigma* signature = (struct sigma*)malloc(sizeof(struct sigma));
    memset(signature, 0, sizeof(struct sigma));

    // 生成此处对应的签名。

    element_t r;
    element_t r_plus;
    element_init_Zr(r, *pk_IDP->pair);
    element_init_Zr(r_plus, *pk_IDP->pair);
    element_random(r);
    element_random(r_plus);

    
    // A_plus \in G1  
    // A_ba \in G1
    element_init_G1(signature->A_plus, *pk_IDP->pair);
    element_init_G1(signature->A_ba, *pk_IDP->pair);

    // 计算A_plus
    element_pow_zn(signature->A_plus, signature_c->A, r);
    
    // 计算A_ba
    //////// 首先计算中间变量，即那个一群连乘 ////////
    // 重写A_ba计算流程
    element_t res;
    element_init_G1(res, *pk_IDP->pair);
    element_t exponent;
    element_init_Zr(exponent, *pk_IDP->pair);

    element_pow_zn(signature->A_ba, signature_c->middle_res, r);

    element_neg(exponent, signature_c->x);
    element_pow_zn(res, signature->A_plus, exponent);

    element_mul(signature->A_ba, signature->A_ba, res);

    //////// 计算A_ba的下一步骤 ////////
    // res in G1
    // exponent in Zr
    
    // 下面计算d
    element_init_G1(signature->d, *pk_IDP->pair);
    element_pow_zn(res, pk_IDP->h_vector[0], r_plus);
    element_pow_zn(signature->d, signature_c->middle_res, r);
    element_mul(signature->d, signature->d, res);

    // 可以试着验证一下下等式
    //////// A_ba = (A')^\gamma ////////
    // 在外界验证，等式成立！

    
    // 又选取了一大堆变量，用于后文的计算
    element_t r_x;
    element_t r_r;
    element_t r_alpha;
    element_t r_beta;
    // 这样写稍微有点浪费空间
    element_t* r_var = (element_t*)malloc(N*sizeof(element_t));

    element_init_Zr(r_x, *pk_IDP->pair);
    element_random(r_x);
    element_init_Zr(r_r, *pk_IDP->pair);
    element_random(r_r);
    element_init_Zr(r_alpha, *pk_IDP->pair);
    element_random(r_alpha);
    element_init_Zr(r_beta, *pk_IDP->pair);
    element_random(r_beta);
    for(int i=0; i<N; i++) {
        element_init_Zr(r_var[i], *pk_IDP->pair);
        element_random(r_var[i]);
    }

    element_t R1;
    element_init_G1(R1, *pk_IDP->pair);
    element_t R2;
    element_init_G1(R2, *pk_IDP->pair);

    

    // 计算R1  res与parcel均为G1群
    // 下文需要改换R1的群
    // res in G1
    // exponent in Zr
    element_neg(exponent, r_x); // -r_x
    element_pow_zn(R1, signature->A_plus, exponent);

    element_pow_zn(res, pk_IDP->h_vector[0], r_r);
    element_mul(R1, res, R1); // 自己乘自己


    // 计算R2
    // res in G1
    // exponent in Zr
    element_pow_zn(R2, signature->d, r_alpha);

    element_neg(exponent, r_beta);
    element_pow_zn(res, pk_IDP->h_vector[0], exponent);
    element_mul(R2, R2, res);
    
    for(int i=1; i<N; i++) {
        // 如果内容被隐藏
        if(is_hidden(select_vector, i)) {
            element_pow_zn(res, pk_IDP->h_vector[i], r_var[i]);
            element_mul(R2, R2, res);
        }
    }

    // 对之前写的复杂流程作了重构优化

    // 得出alpha 与 beta

    
    element_t alpha;
    element_t beta;
    element_init_Zr(alpha, *pk_IDP->pair);
    element_init_Zr(beta, *pk_IDP->pair);

    //// 取逆 ////
    element_invert(alpha, r);
    element_mul(beta, alpha, r_plus);
    element_add(beta, beta, signature_c->s);

    // 计算hash值

    
    int H_length = 0;
    int A_plus_length = 0, A_ba_length = 0, d_length = 0, R1_length = 0, R2_length = 0;

    A_plus_length = element_length_in_bytes(signature->A_plus);
    A_ba_length = element_length_in_bytes(signature->A_ba);
    d_length = element_length_in_bytes(signature->d);
    R1_length = element_length_in_bytes(R1);
    R2_length = element_length_in_bytes(R2);

    H_length = A_plus_length + A_ba_length + d_length + R1_length + R2_length;

    unsigned char* data_buffer = (unsigned char*)malloc(H_length*sizeof(unsigned char));
    memset(data_buffer, 0, H_length*sizeof(unsigned char));
    // 最后没有必要补\0

    
    unsigned char* tmp_buffer = data_buffer;
    element_to_bytes(tmp_buffer, signature->A_plus);
    tmp_buffer += A_plus_length;
    element_to_bytes(tmp_buffer, signature->A_ba);
    tmp_buffer += A_ba_length;
    element_to_bytes(tmp_buffer, signature->d);
    tmp_buffer += d_length;
    element_to_bytes(tmp_buffer, R1);
    tmp_buffer += R1_length;
    element_to_bytes(tmp_buffer, R2);
    // tmp_buffer += R2_length;

    
    // void hash_SHA256(unsigned char* data_buffer, int length, unsigned char result[])
    unsigned char result[32] = {0};
    hash_SHA256(data_buffer, H_length, result);
    // printf(result);
    // 反向映射到Z_r域
    element_init_Zr(signature->c, *pk_IDP->pair);
    //////////// 重要的哈希函数位置  写注释提醒自己 ////////////
    element_from_hash(signature->c, result, 32); // sha256's length is always 32

    // 计算最后的一堆z值
    
    
    // z_x
    element_init_Zr(signature->z_x, *pk_IDP->pair);
    element_mul(signature->z_x, signature->c, signature_c->x);
    element_add(signature->z_x, signature->z_x, r_x);
    // z_r
    element_init_Zr(signature->z_r, *pk_IDP->pair);
    element_mul(signature->z_r, signature->c, r_r);
    element_add(signature->z_r, signature->z_r, r_plus);
    // z_alpha
    element_init_Zr(signature->z_alpha, *pk_IDP->pair);
    element_mul(signature->z_alpha, signature->c, alpha);
    element_add(signature->z_alpha, signature->z_alpha, r_alpha);
    // z_beta
    element_init_Zr(signature->z_beta, *pk_IDP->pair);
    element_mul(signature->z_beta, signature->c, beta);
    element_add(signature->z_beta, signature->z_beta, r_beta);

    // z_i
    signature->z_i_hidden = (element_t *)malloc(N*sizeof(element_t));
    for(int i=1; i<N; i++) {
        // 不论如何，采用全部初始化的原则
        element_init_Zr(signature->z_i_hidden[i], *pk_IDP->pair);
        
        if(is_hidden(select_vector, i)) {
            // 如果是被隐藏的element，那么初始化并且赋值
            element_mul(signature->z_i_hidden[i], signature->c, m_vector[i]);
            element_add(signature->z_i_hidden[i], signature->z_i_hidden[i], r_var[i]);
        }
    }

    // 计算完毕，释放多余的空间

    element_clear(r);
    element_clear(r_plus);

    element_clear(res);
    element_clear(exponent);

    element_clear(r_x);
    element_clear(r_r);
    element_clear(r_alpha);
    element_clear(r_beta);
    for(int i=0; i<N; i++) {
        element_clear(r_var[i]);
    }
    free(r_var);

    element_clear(R1);
    element_clear(R2);

    element_clear(alpha);
    element_clear(beta);

    free(data_buffer);

    
    return signature;
}