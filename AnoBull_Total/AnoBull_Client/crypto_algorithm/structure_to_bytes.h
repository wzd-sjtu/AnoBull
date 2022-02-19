#ifndef __STRUCT_TO_BYTES
#define __STRUCT_TO_BYTES

#include "all_def.h"

// for pk_IDP
int pk_IDP_to_bytes(struct public_key_IDP* pk_IDP, char* thread_send_buffer, int data_len_limit);
struct public_key_IDP* pk_IDP_from_bytes(unsigned char* data_buffer, int length);
int comapre_pk_IDP(struct public_key_IDP* pk_IDP, struct public_key_IDP* new_pk_IDP);

#endif
