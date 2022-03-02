#ifndef __STRUCT_TO_BYTES
#define __STRUCT_TO_BYTES

#include "all_def.h"

// for pk_IDP
struct public_key_IDP* pk_IDP_from_bytes(unsigned char* data_buffer);
int comapre_pk_IDP(struct public_key_IDP* pk_IDP, struct public_key_IDP* new_pk_IDP);
struct sigma_c* sigma_c_from_bytes(char* data_buffer, int length, struct public_key_IDP* pk_IDP);

// int sigma_to_bytes(struct sigma* will_send_sigma, char* data_buffer, int data_len_limit);
int sigma_to_bytes(struct sigma* will_send_sigma, char* data_buffer, int data_len_limit, struct public_key_IDP* pk_IDP);
struct sigma* sigma_from_bytes(char* data_buffer, int length, struct public_key_IDP* pk_IDP);

int filling_selected_m_vector_into_buffer(char* data_buffer, element_t* m_vector, char* select_vector, \
    struct public_key_IDP* pk_IDP);

#endif
