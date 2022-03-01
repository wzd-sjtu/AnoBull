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


// 将list转换为对应的vector
element_t* convert_info_to_vector(struct list* user_info_list_specific, struct public_key_IDP* pk_IDP) {
    // element_init_Zr

    // 信息序列的维度
    int N = pk_IDP->total_num_of_h_i;
    // printf("the number of N is %d\n", N);

    // add a 强制类型转换
    element_t* m_vector = (element_t*)malloc(N*sizeof(element_t));

    
    for(int i=0; i<N; i++) {
        element_init_Zr(m_vector[i], *pk_IDP->pair);
    }
    
    // 进行维度映射
    // printf("begin compare it:\n");
    // printf("what happened?? num is %d\n", user_info_list_specific->list_num);

    // 就是这里的traverse进行了遍历处理，头疼
    // traverse_show_list(user_info_list_specific);
    struct list_node* tmp_node = user_info_list_specific->vir_head->next;
    
    
    for(int i=0; i<N; i++) {
        // 进行简单的映射
        // void element_from_hash(element_t e, void *data, int len)
        element_from_hash(m_vector[i], (char*)tmp_node->val2, strlen((char*)tmp_node->val2));

        tmp_node = tmp_node->next;
    }
    // 完成内容的拼写，为后文的传送打下一定的基础
    
    // printf("complete it! damn it!!\n");
    return m_vector;
}


void hash_SHA256(unsigned char* data_buffer, int length, unsigned char result[]) {
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, data_buffer, length);

    SHA256_Final(result, &sha256_ctx);
    return;
}

// 需要加入一个hidden_vector
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


    // 得出alpha 与 beta

    
    element_t alpha;
    element_t beta;
    element_init_Zr(alpha, *pk_IDP->pair);
    element_init_Zr(beta, *pk_IDP->pair);

    //// 取逆 ////  -1 与 inverse是完全相同的喽
    element_invert(alpha, r);
    //element_set1(exponent);
    //element_neg(exponent, exponent);
    //element_pow_zn(alpha, r, exponent);

    element_mul(beta, alpha, r_plus);
    element_add(beta, beta, signature_c->s);

    /*
    // 这里中间验证一下是否成立？
    // 验证通过
    element_t temp1, temp2;
    element_init_G1(temp1, *pk_IDP->pair);
    element_init_G1(temp2, *pk_IDP->pair);

    element_pow_zn(temp1, signature->d, alpha);

    element_mul(exponent, alpha, r_plus);
    element_pow_zn(res, pk_IDP->h_vector[0], exponent);
    element_mul(temp2, res, signature_c->middle_res);


    if (!element_cmp(temp1, temp2)) {
        printf("alpha and beta verifies\n");
    } else {
        printf("alpha and beta does not verify\n");
    }
    */


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


    // 计算hash值

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
    element_mul(signature->z_r, signature->c, r_plus);
    element_neg(signature->z_r, signature->z_r);
    element_add(signature->z_r, signature->z_r, r_r);

    // z_alpha
    element_init_Zr(signature->z_alpha, *pk_IDP->pair);
    element_mul(signature->z_alpha, signature->c, alpha);
    element_add(signature->z_alpha, signature->z_alpha, r_alpha);
    // z_beta
    element_init_Zr(signature->z_beta, *pk_IDP->pair);
    element_mul(signature->z_beta, signature->c, beta);
    element_add(signature->z_beta, signature->z_beta, r_beta);

    // z_i
    // 最好的方式便是做减法即可
    signature->z_i_hidden = (element_t *)malloc(N*sizeof(element_t));

    element_init_Zr(signature->z_i_hidden[0], *pk_IDP->pair);
    for(int i=1; i<N; i++) {
        // 不论如何，采用全部初始化的原则
        element_init_Zr(signature->z_i_hidden[i], *pk_IDP->pair);
        if(is_hidden(select_vector, i)) {
            // 如果是被隐藏的element，那么初始化并且赋值
            element_mul(signature->z_i_hidden[i], signature->c, m_vector[i]);
            element_sub(signature->z_i_hidden[i], signature->z_i_hidden[i], r_var[i]);
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
