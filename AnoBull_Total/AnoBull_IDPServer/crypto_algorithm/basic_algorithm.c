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


void hash_SHA256(unsigned char* data_buffer, int length, unsigned char result[]) {
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, data_buffer, length);

    SHA256_Final(result, &sha256_ctx);
    return;
}

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

        // h_0 ^ s
    element_pow_zn(parcel, pk_IDP->h_vector[0], signature_c->s);
    element_set(res, parcel);

    int N = pk_IDP->total_num_of_h_i;
        // h_0 ^ s \sum h_i ^ m_i(仅仅涉及公开信息m_i)

        // 关于selector_vector的注意范围是？暂时是不太清楚的了
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

// 将list转换为对应的vector，也就是信息序列vector，对的了
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

    // traverse_show会造成终端输出混乱，并不适合处理+操作
    // traverse_show_list(user_info_list_specific);
    struct list_node* tmp_node = user_info_list_specific->vir_head->next;
    
    // 这个m_vector需要更新其对应的维度
    element_random(m_vector[0]);
    for(int i=1; i<N; i++) {
        // 进行简单的映射
        // void element_from_hash(element_t e, void *data, int len)

        // 对message进行了基本的映射转换
        element_from_hash(m_vector[i], (char*)tmp_node->val2, strlen((char*)tmp_node->val2));

        tmp_node = tmp_node->next;
    }
    // 完成内容的拼写，为后文的传送打下一定的基础
    

    // 这里处理的是把用户信息转换为vector的过程
    // printf("complete it! damn it!!\n");
    return m_vector;
}


element_t* get_the_m_vector(char* data_buffer, struct public_key_IDP* pk_IDP) {
    element_t* res_vector = (element_t*)malloc(pk_IDP->total_num_of_h_i * sizeof(element_t));

    // 空间分配
    int tmp_len = 0;
    element_t* tmp_pointer = NULL;

    for(int i=0; i<pk_IDP->total_num_of_h_i; i++) {
        tmp_len = 0;
        // True代表有数据，想要把数据展现出来
        if(data_buffer[2] == 'T') {
            // 表示后文有对应的information
            data_buffer += 3;
            
            element_init_Zr(res_vector[i], *pk_IDP->pair);

            data_buffer += element_from_bytes(res_vector[i], data_buffer);
        }
        // False代表没有数据，想要把数据隐藏起来
        else {
            // 表示后文没有对应的information
            data_buffer += 3;

            // 置为NULL，表示数据被隐藏了
            // free是不可行的
            element_init_Zr(res_vector[i], *pk_IDP->pair);
            // data_buffer += element_from_bytes(res_vector[i], HIDDEN_INFO_CHARS);
        }
    }
    return res_vector;
}

char* get_selector_vector(element_t* m_vector, struct public_key_IDP* pk_IDP) {
    // 马上就到了代码写完的境界了
    int N = pk_IDP->total_num_of_h_i;
    char* selector_vector = (char*)malloc(N*sizeof(char));

    element_t* tmp = m_vector;
    for(int i=0; i<N; i++) {
        if(tmp == NULL) {
            selector_vector[i] = 1;
        }
        else {
            selector_vector[i] = 0;
        }
        tmp++;
    }

    return selector_vector;
}


struct m_vector_and_selector_struct* get_the_m_vector_and_selector_vector(char* data_buffer, struct public_key_IDP* pk_IDP) {
    element_t* res_vector = (element_t*)malloc(pk_IDP->total_num_of_h_i * sizeof(element_t));
    char* selector_vector = (char*)malloc(pk_IDP->total_num_of_h_i * sizeof(char));
    // 空间分配
    int tmp_len = 0;
    element_t* tmp_pointer = NULL;

    // printf("[DEBUG DEBUG WHAT HAPPENED?]");
    for(int i=0; i<pk_IDP->total_num_of_h_i; i++) {
        tmp_len = 0;
        // True代表有数据，想要把数据展现出来
        if(data_buffer[2] == 'T') {
            // 表示后文有对应的information
            data_buffer += 3;
            
            element_init_Zr(res_vector[i], *pk_IDP->pair);

            data_buffer += element_from_bytes(res_vector[i], data_buffer);

            selector_vector[i] = 0;
        }
        // False代表没有数据，想要把数据隐藏起来
        else {
            // 表示后文没有对应的information
            data_buffer += 3;

            // 置为NULL，表示数据被隐藏了
            // free是不可行的
            element_init_Zr(res_vector[i], *pk_IDP->pair);
            element_random(res_vector[i]);

            // 表示数据被隐藏
            selector_vector[i] = 1;
        }
    }

    struct m_vector_and_selector_struct* res = (struct m_vector_and_selector_struct*)malloc(sizeof(struct m_vector_and_selector_struct));
    res->m_vector = res_vector;
    res->selector_vector = selector_vector;

    return res;
}


// 在RP_verify时，记得返回中间的一个缓存变量
element_t* RP_verify(struct sigma* signature, element_t* m_vector, char* select_vector, \
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

    // R2是需要缓存的内容，记得不要清理掉
    // element_clear(R2);
    element_clear(res);
    element_clear(exponent);

    element_clear(temp1);
    element_clear(temp2);

    element_clear(c_reproduce);

    free(data_buffer);

    // 返回R2的地址即可
    return &R2;
}

struct sigma_store* init_sigma_store(struct sigma* recvived_signature, element_t* R2_will_cache, struct public_key_IDP* pk_IDP) {
    struct sigma_store* cached_signature = (struct sigma_store*)malloc(sizeof(struct sigma_store));

    element_init_G1(cached_signature->A_plus, *pk_IDP->pair);
    element_init_G1(cached_signature->A_ba, *pk_IDP->pair);
    element_init_G1(cached_signature->d, *pk_IDP->pair);
    element_init_G1(cached_signature->R2, *pk_IDP->pair);

    element_init_Zr(cached_signature->c, *pk_IDP->pair);
    element_init_Zr(cached_signature->z_x, *pk_IDP->pair);
    element_init_Zr(cached_signature->z_r, *pk_IDP->pair);
    element_init_Zr(cached_signature->z_alpha, *pk_IDP->pair);
    element_init_Zr(cached_signature->z_beta, *pk_IDP->pair);

    int N = pk_IDP->total_num_of_h_i;
    for(int i=0; i<N; i++) {
        element_init_Zr(cached_signature->z_i_hidden[i], *pk_IDP->pair);
    }

    // 之后进行赋值即可
    element_set(cached_signature->A_plus, recvived_signature->A_plus);
    element_set(cached_signature->A_ba, recvived_signature->A_ba);
    element_set(cached_signature->d, recvived_signature->d);
    element_set(cached_signature->R2, *R2_will_cache);

    element_set(cached_signature->c, recvived_signature->c);
    element_set(cached_signature->z_x, recvived_signature->z_x);
    element_set(cached_signature->z_r, recvived_signature->z_r);
    element_set(cached_signature->z_alpha, recvived_signature->z_alpha);
    element_set(cached_signature->z_beta, recvived_signature->z_beta);

    for(int i=0; i>N; i++) {
        element_set(cached_signature->z_i_hidden[i], recvived_signature->z_i_hidden[i]);
    }
    // 完成上文处理后，还需要存入一个selector vector，当做冗余信息存储在数据库里面即可
    // 还需要补充一个selector_vector，这个表格不需要添加别的信息了

    return cached_signature;
}