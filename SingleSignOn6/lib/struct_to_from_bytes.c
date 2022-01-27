#include "CLIENT_compute.h"
#include "IDP_audit.h"
#include "IDP_init.h"


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

    
    unsigned char* tmp_buffer = data_buffer;
    element_to_bytes(tmp_buffer, pk_IDP->omega);
    tmp_buffer += omega_length;
    for(int i=0; i<pk_IDP->total_num_of_h_i; i++) {
        element_to_bytes(tmp_buffer, pk_IDP->h_vector[i]);
        tmp_buffer += each_h_vector_length;
    }
    
    // store into it, use int function
    memcpy(tmp_buffer, &pk_IDP->total_num_of_h_i, sizeof(int));
    tmp_buffer += total_num_of_h_i_length;
    

    memcpy(tmp_buffer, pair_choice, strlen(pair_choice));
    tmp_buffer[strlen(pair_choice)] = '\0';
    tmp_buffer += pair_length;

    element_to_bytes(tmp_buffer, pk_IDP->g1);
    tmp_buffer += g1_length;
    element_to_bytes(tmp_buffer, pk_IDP->g2);
    tmp_buffer += g2_length;

    data_buffer[H_length-1] = '\0';

    return data_buffer;
}