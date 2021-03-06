#include "RP_verify.h"


int RP_verify(struct sigma* signature, element_t* m_vector, char* select_vector, \
    struct public_key_IDP* pk_IDP) {
    
    // 恢复出R1和R2
    element_t R1;
    element_init_G1(R1, *pk_IDP->pair);
    element_t R2;
    element_init_G1(R2, *pk_IDP->pair);

    element_t res;
    element_init_G1(res, *pk_IDP->pair);
    element_t exponent;
    element_init_Zr(exponent, *pk_IDP->pair);

    
    // 恢复R1
    element_neg(exponent, signature->z_x);
    element_pow_zn(R1, signature->A_plus, exponent);

    element_pow_zn(res, pk_IDP->h_vector[0], signature->z_r);
    element_mul(R1, R1, res); // 将中间变量乘上去即可得之

    element_neg(exponent, signature->c);
    element_div(res, signature->A_ba, signature->d);
    element_pow_zn(res, res, exponent);

    element_mul(R1, R1, res);

    
    // 恢复R2
    element_set1(R2);
    // data 总是从 下标1开始
    for(int i=1; i<pk_IDP->total_num_of_h_i; i++) {
        if(!is_hidden(select_vector, i)) {
            element_pow_zn(res, pk_IDP->h_vector[i], m_vector[i]);
            element_mul(R2, R2, res);
        }
    }
    
    element_mul(R2, R2, pk_IDP->g1); // 漏了一个公式

    element_neg(exponent, signature->c);
    element_pow_zn(R2, R2, exponent);

    element_neg(exponent, signature->z_beta);
    element_pow_zn(res, pk_IDP->h_vector[0], exponent);
    element_mul(R2, R2, res);
    
    element_pow_zn(res, signature->d, signature->z_alpha);
    element_mul(R2, R2, res);

    // 下标总是从1开始
    for(int i=1; i<pk_IDP->total_num_of_h_i; i++) {
        if(is_hidden(select_vector, i)) {
            element_neg(exponent, signature->z_i_hidden[i]);
            element_pow_zn(res, pk_IDP->h_vector[i], exponent);
            element_mul(R2, R2, res);
        }
    }

    // 完成R1与R2的恢复后，进行最终的验证环节：


    element_t temp1, temp2;
    element_init_GT(temp1, *pk_IDP->pair);
    element_init_GT(temp2, *pk_IDP->pair);

    pairing_apply(temp1, signature->A_ba, pk_IDP->g2, *pk_IDP->pair);
    pairing_apply(temp2, signature->A_plus, pk_IDP->omega, *pk_IDP->pair);
    if (!element_cmp(temp1, temp2)) {
        printf("equation 3 signature verifies\n");
    } else {
        printf("equation 3 signature does not verify\n");
    }


    

    // 恢复签名c
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
    // 成功得到暂时的结果，需要反向映射回去

    // 所以究竟发生了什么事情？verify暂时是失败的了
    element_t c_reproduce;
    element_init_Zr(c_reproduce, *pk_IDP->pair);
    element_from_hash(c_reproduce, result, 32); // sha256's length is always 32

    // 签名of c再次失败了！
    if (!element_cmp(c_reproduce, signature->c)) {
        printf("equation 4 signature verifies\n");
    } else {
        printf("equation 4 signature does not verify\n");
    }
    // 至此完成整个算法过程的编写
    

    // 删除中间变量
    
    element_clear(R1);
    element_clear(R2);
    element_clear(res);
    element_clear(exponent);

    element_clear(temp1);
    element_clear(temp2);

    element_clear(c_reproduce);

    free(data_buffer);
    return 1;
}
