#include "IDP_init.h"
#include "CLIENT_compute.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// 运行指令如下：
// ./build/kernel.bin
int main() {

    // 初始化群空间

    
    char* name = "D224";
    pairing_t* pair_use;
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
    element_clear(temp1);
    element_clear(temp2);
    element_clear(tmp);

    // Client验证完成后，再进行个性化签名
    
    char* select_vector = (char*)malloc(N*sizeof(char));
    memset(select_vector, 0, N*sizeof(char)); // 是否要全部刷0？有时是无必要的
    
    select_vector[4] = 1;
    select_vector[3] = 1;
    select_vector[1] = 1;

    // 完成complete？

    struct sigma* signature;
    signature = compute_sigma(signature_c, pk_IDP, m_vector, select_vector);
    

    // 验证A_plus与A_ba计算是否正确

    element_init_G1(temp1, *pk_IDP->pair);

    element_pow_zn(temp1, signature->A_plus, sk_IDP->gamma);

    if (!element_cmp(temp1, signature->A_ba)) {
        printf("A and A_ba equation 2 verifies\n");
    } else {
        printf("A and A_ba equation 2 does not verify\n");
    }
    // 用完的变量记得clear
    element_clear(temp1);

    // 成功完成所有变量，下面对别的参数进行处理
    
   
    while(1);
    return 0;
}