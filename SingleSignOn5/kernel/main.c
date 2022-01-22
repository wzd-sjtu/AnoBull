#include "IDP_init.h"
#include "CLIENT_compute.h"
#include "RP_verify.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void clear_all(struct public_key_IDP* pk_IDP, struct secret_key_IDP* sk_IDP, \
    struct sigma_c* signature_c, struct sigma* signature) {

    int N = pk_IDP->total_num_of_h_i;

    
    element_clear(pk_IDP->omega);
    for(int i=0; i<N; i++) {
        element_clear(pk_IDP->h_vector[i]);
    }
    
    free(pk_IDP->h_vector);
    element_clear(pk_IDP->g1);
    element_clear(pk_IDP->g2);
    element_clear(sk_IDP->gamma);

    
    element_clear(signature_c->x);
    element_clear(signature_c->s);
    element_clear(signature_c->A);
    element_clear(signature_c->middle_res);

    
    element_clear(signature->A_plus);
    element_clear(signature->A_ba);
    element_clear(signature->d);
    element_clear(signature->c);
    element_clear(signature->z_x);
    element_clear(signature->z_r);
    element_clear(signature->z_alpha);
    element_clear(signature->z_beta);

    
    for(int i=0; i<N; i++) {
        // 这里需要选择一下，无语ing
        element_clear(signature->z_i_hidden[i]);
    }
    free(signature->z_i_hidden);
    return;
}


// 运行指令如下：
// ./build/kernel.bin
int main() {

    // 初始化群空间

    
    char* name = "D224";
    pairing_t* pair_use; // 典型的野指针，难以理解的大问题
    pair_use = init_space(name); // it is always a pointer

    // 生成IDP私钥
    struct secret_key_IDP* sk_IDP = NULL;
    sk_IDP = init_IDP_secret_key(pair_use);

    // 生成IDP公钥，需要一个参数N
    int N = 6;
    struct public_key_IDP* pk_IDP = NULL;
    pk_IDP = init_IDP_public_key(pair_use, N, sk_IDP);
    
    // IDP对消息做一个签名

    // 生成初始消息
    element_t* m_vector = (element_t*)malloc(N*sizeof(element_t));
    for(int i=0; i<N; i++) {
        element_init_Zr(m_vector[i], *pair_use);
        element_random(m_vector[i]);
    }
    // 计算初始签名 sigma_c
    struct sigma_c* signature_c = compute_sigma_c(m_vector, pk_IDP, sk_IDP);
    
    // Client验证此签名是否成立？
    element_t temp1, temp2;
    element_init_GT(temp1, *pk_IDP->pair);
    element_init_GT(temp2, *pk_IDP->pair);

    element_t tmp;element_init_G2(tmp, *pk_IDP->pair);
    element_pow_zn(tmp, pk_IDP->g2, signature_c->x);
    element_mul(tmp, tmp, pk_IDP->omega);

    // 进行等式左边映射
    pairing_apply(temp1, signature_c->A,tmp, *pk_IDP->pair);

    // 进行等式右边映射
    pairing_apply(temp2, signature_c->middle_res, pk_IDP->g2, *pk_IDP->pair);

    if (!element_cmp(temp1, temp2)) {
        printf("signature_c equation 1 verifies\n");
    } else {
        printf("signature_c equation 1 does not verify\n");
    }
    // 用完的变量记得clear

    // Client验证完成后，再进行个性化签名
    
    char* select_vector = (char*)malloc(N*sizeof(char));
    memset(select_vector, 0, N*sizeof(char)); // 是否要全部刷0？有时是无必要的
    
    select_vector[4] = 1;
    select_vector[3] = 1;
    select_vector[1] = 1;

    // 完成complete？

    
    struct sigma* signature = NULL;
    signature = compute_sigma(signature_c, pk_IDP, m_vector, select_vector);
    

    // 验证A_plus与A_ba计算是否正确

    element_init_G1(temp1, *pk_IDP->pair);

    element_pow_zn(temp1, signature->A_plus, sk_IDP->gamma);

    if (!element_cmp(temp1, signature->A_ba)) {
        printf("A and A_ba equation 2 verifies\n");
    } else {
        printf("A and A_ba equation 2 does not verify\n");
    }
    
    
    // 成功完成所有变量，下面对别的参数进行处理

    RP_verify(signature, m_vector, select_vector, pk_IDP);

    
    clear_all(pk_IDP, sk_IDP, signature_c, signature);
    
    
    element_clear(temp1);
    element_clear(temp2);
    element_clear(tmp);
    for(int i=0; i<N; i++) {
        element_clear(m_vector[i]);
    }
    free(m_vector);
    free(select_vector); // empty all spaces
    
    free(sk_IDP);

    free(signature);
    free(signature_c);

    free(pk_IDP);
    // 指针要最后empty掉
    pairing_clear(*pair_use);


    while(1);
    return 0;
}