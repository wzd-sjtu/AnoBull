#include "stdio.h"
#include "stdlib.h"
#include "structure_to_bytes.h"
#include "/usr/local/include/pbc/pbc.h"
#include "/usr/local/include/pbc/pbc_test.h"
#include "basic_algorithm.h"

// just to element is ok for me

// 本文件目前只实现了公钥的内容转换，仍然有许多许多小问题

// length是可以在网络通信中完成传递的
struct public_key_IDP* pk_IDP_from_bytes(unsigned char* data_buffer) {
    // needed to use the API
    // int element_from_bytes(element_t e, unsigned char *data)
    int H_length = 0;
    int omega_length = 0, h_vector_length = 0, \
        g1_length = 0, g2_length = 0;

    int total_num_of_h_i_length = sizeof(int);

    int each_h_vector_length = 0;
    int pair_length = 8;

    char pair_choice[8] = {0};

    // 这里进行了公钥的生成
    // 考虑到公钥只生成一次，所以写在哪里是无所谓的了
    struct public_key_IDP* res_pk_IDP = (struct public_key_IDP*)malloc(sizeof(struct public_key_IDP));
    
    unsigned char* tmp_buffer = data_buffer;

    
    // using the pair choice to initialize the pair
    memcpy(pair_choice, tmp_buffer, pair_length);
    tmp_buffer += pair_length;
    // printf("pair choice is %s\n", pair_choice);

    // printf("chosen group is ");
    // printf(pair_choice);
    // printf("\n");

    // init the pair space, what happened?? should be initialized the pair firstly?
    res_pk_IDP->pair = init_space(pair_choice);
    // then set the group of element

    // 为何初始化会失败？？难以理解

    element_init_G2(res_pk_IDP->omega, *res_pk_IDP->pair);
    element_init_G1(res_pk_IDP->g1, *res_pk_IDP->pair);
    element_init_G2(res_pk_IDP->g2, *res_pk_IDP->pair);

    
    
    // always from order to implement the data_buffer
    memcpy(&res_pk_IDP->total_num_of_h_i, tmp_buffer, sizeof(int));
    tmp_buffer += total_num_of_h_i_length;  // store into the length of idp
    int N = res_pk_IDP->total_num_of_h_i;

    // printf("chose h_vector dimentions are %d \n", N);

    omega_length = element_from_bytes(res_pk_IDP->omega, tmp_buffer);
    tmp_buffer += omega_length;

    
    // firstly to read the each h_length
    // initialize of h_i, for use of h_vector
    res_pk_IDP->h_vector = (element_t *)malloc(N*sizeof(element_t));
    // each_h_vector_length = element_from_bytes(res_pk_IDP->h_vector[0], tmp_buffer);
    // tmp_buffer += each_h_vector_length;
    for(int i=0; i<N; i++) {
        // firstly initialize the space
        element_init_G1(res_pk_IDP->h_vector[i], *res_pk_IDP->pair);
        each_h_vector_length = element_from_bytes(res_pk_IDP->h_vector[i], tmp_buffer);
        tmp_buffer += each_h_vector_length;
    }

    
    g1_length = element_from_bytes(res_pk_IDP->g1, tmp_buffer);
    tmp_buffer += g1_length;

    g2_length = element_from_bytes(res_pk_IDP->g2, tmp_buffer);
    tmp_buffer += g2_length;
    
    return res_pk_IDP;
}

int comapre_pk_IDP(struct public_key_IDP* pk_IDP, struct public_key_IDP* new_pk_IDP) {
    int res = 0;
    if(element_cmp(pk_IDP->omega, new_pk_IDP->omega) != 0) {
        // printf("yes!");
        return 0;
    }
    if(pk_IDP->total_num_of_h_i != new_pk_IDP->total_num_of_h_i) {
        return 0;
    }
    for(int i=0; i<pk_IDP->total_num_of_h_i; i++) {
        if(element_cmp(pk_IDP->h_vector[i], new_pk_IDP->h_vector[i]) != 0) {
            return 0;
        }
    }
    if(element_cmp(pk_IDP->g1, new_pk_IDP->g1) != 0) {
        return 0;
    }
    if(element_cmp(pk_IDP->g2, new_pk_IDP->g2) != 0) {
        return 0;
    }
    return 1;
}


struct sigma_c* sigma_c_from_bytes(char* data_buffer, int length, struct public_key_IDP* pk_IDP) {
    // 下面对thing做一个恢复
    // 这个api对于user端来说，也是成立的
    struct sigma_c* res_sigma_c = (struct sigma_c*)malloc(sizeof(struct sigma_c));

    element_init_Zr(res_sigma_c->x, *pk_IDP->pair);
    element_init_Zr(res_sigma_c->s, *pk_IDP->pair);

    element_init_G1(res_sigma_c->A, *pk_IDP->pair);

    element_init_G1(res_sigma_c->middle_res, *pk_IDP->pair);

    char* tmp_buffer = data_buffer;

    int tmp_len = 0;

    tmp_len = element_from_bytes(res_sigma_c->x, tmp_buffer);
    tmp_buffer += tmp_len;

    tmp_len = element_from_bytes(res_sigma_c->s, tmp_buffer);
    tmp_buffer += tmp_len;

    tmp_len = element_from_bytes(res_sigma_c->A, tmp_buffer);
    tmp_buffer += tmp_len;

    tmp_len = element_from_bytes(res_sigma_c->middle_res, tmp_buffer);
    tmp_buffer += tmp_len;

    // successfully get the target result.
    return res_sigma_c;
}


