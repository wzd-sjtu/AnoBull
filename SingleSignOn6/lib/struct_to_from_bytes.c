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

    // should be pair transtmitted? no useful?
    pair_length = element_length_in_bytes(*pk_IDP->pair);
    g1_length = element_length_in_bytes(pk_IDP->g1);
    g2_length = element_length_in_bytes(pk_IDP->g2);

    H_length = omega_length + h_vector_length + pair_length + \
        g1_length + g2_length;

    total_num_of_h_i_length = sizeof(pk_IDP->total_num_of_h_i);
    total_num_of_h_i_length = total_num_of_h_i_length/sizeof(unsigned char);

    H_length += (total_num_of_h_i_length + 1);
    // only nothing to store, right? 
    unsigned char* data_buffer = (unsigned char*)malloc(H_length*sizeof(unsigned char), );
    memset(data_buffer, 0, H_length*sizeof(unsigned char));
    // 对于别的选择，最后会补一个斜杠0表示终止

    
    unsigned char* tmp_buffer = data_buffer;
    element_to_bytes(tmp_buffer, pk_IDP->omega);
    tmp_buffer += omega_length;
    for(int i=0; i<pk_IDP->total_num_of_h_i; i++) {
        element_to_bytes(tmp_buffer, pk_IDP->h_vector[i]);
        tmp_buffer += each_h_vector_length;
    }
    
    element_to_bytes(tmp_buffer, );
    tmp_buffer += d_length;
    element_to_bytes(tmp_buffer, R1);
    tmp_buffer += R1_length;
    element_to_bytes(tmp_buffer, R2);
    // tmp_buffer += R2_length;
}