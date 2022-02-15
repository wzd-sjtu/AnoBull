#include "CLIENT_compute.h"
#include "IDP_audit.h"
#include "IDP_init.h"
#include "stdio.h"
#include "stdlib.h"

// just to element is ok for me
unsigned char* pk_IDP_to_bytes(struct public_key_IDP* pk_IDP) {
    int H_length = 0;
    int omega_length = 0, h_vector_length = 0, total_num_of_h_i_length = 0, \
        pair_length = 0, g1_length = 0, g2_length = 0;
    int each_h_vector_length = 0;

    

    omega_length = element_length_in_bytes(pk_IDP->omega);

    each_h_vector_length = element_length_in_bytes(pk_IDP->h_vector[0]);
    h_vector_length = each_h_vector_length*pk_IDP->total_num_of_h_i;

    // about how to audit? there is no necessary method to implement the project
    // should be pair transtmitted? no useful?

    // pair should be initialized in the local
    // just need a function
    // pair_length = element_length_in_bytes(*pk_IDP->pair);

    char* pair_choice = "D224";
    pair_length = 8; // give 8 bytes to store pair_choice

    g1_length = element_length_in_bytes(pk_IDP->g1);
    g2_length = element_length_in_bytes(pk_IDP->g2);

    H_length = omega_length + h_vector_length + pair_length + \
        g1_length + g2_length;

    total_num_of_h_i_length = sizeof(pk_IDP->total_num_of_h_i);
    total_num_of_h_i_length = total_num_of_h_i_length/sizeof(unsigned char);

    H_length += (total_num_of_h_i_length + 1);  // 最后要补一个\0,标志着字符串的结束


    // only nothing to store, right? 
    unsigned char* data_buffer = (unsigned char*)malloc(H_length*sizeof(unsigned char));
    memset(data_buffer, 0, H_length*sizeof(unsigned char));
    // 对于别的选择，最后会补一个斜杠0表示终止

    
    // store into it, use int function
    // firstly store the total_number 
    unsigned char* tmp_buffer = data_buffer;

    memcpy(tmp_buffer, pair_choice, strlen(pair_choice));
    // tmp_buffer[strlen(pair_choice)] = '\0';
    for(int love = strlen(pair_choice); love < pair_length; love++) {
        tmp_buffer[love] = '\0';
    }
    tmp_buffer += pair_length;

    memcpy(tmp_buffer, &pk_IDP->total_num_of_h_i, sizeof(int));
    tmp_buffer += sizeof(int);

    
    omega_length = element_to_bytes(tmp_buffer, pk_IDP->omega);

    element_t tmp_omega;
    element_init_G2(tmp_omega, *pk_IDP->pair);
    int another_len = element_from_bytes(tmp_omega, tmp_buffer);
    printf("\n pre num is %d, next num is %d \n", omega_length, another_len);

    // there should be \0 stored into it?
    if(element_cmp(tmp_omega, pk_IDP->omega)==0) {
        printf("\n failed it! \n");
    }

    tmp_buffer += omega_length;

    for(int i=0; i<pk_IDP->total_num_of_h_i; i++) {
        element_to_bytes(tmp_buffer, pk_IDP->h_vector[i]);
        tmp_buffer += each_h_vector_length;
    }
    
    
    element_to_bytes(tmp_buffer, pk_IDP->g1);
    tmp_buffer += g1_length;
    element_to_bytes(tmp_buffer, pk_IDP->g2);
    tmp_buffer += g2_length;

    data_buffer[H_length-1] = '\0';

    return data_buffer;
}

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

    struct public_key_IDP* res_pk_IDP = (struct public_key_IDP*)malloc(sizeof(struct public_key_IDP));
    
    unsigned char* tmp_buffer = data_buffer;

    
    // using the pair choice to initialize the pair
    memcpy(pair_choice, tmp_buffer, pair_length);
    tmp_buffer += pair_length;

    printf("chosen group is ");
    printf(pair_choice);
    printf("\n");

    // init the pair space, what happened?? should be initialized the pair firstly?
    res_pk_IDP->pair = init_space(pair_choice);
    // then set the group of element

    
    element_init_G2(res_pk_IDP->omega, *res_pk_IDP->pair);
    element_init_G1(res_pk_IDP->g1, *res_pk_IDP->pair);
    element_init_G2(res_pk_IDP->g2, *res_pk_IDP->pair);

    
    
    // always from order to implement the data_buffer
    memcpy(&res_pk_IDP->total_num_of_h_i, tmp_buffer, sizeof(int));
    tmp_buffer += total_num_of_h_i_length;  // store into the length of idp
    int N = res_pk_IDP->total_num_of_h_i;

    printf("chose h_vector dimentions are %d \n", N);

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