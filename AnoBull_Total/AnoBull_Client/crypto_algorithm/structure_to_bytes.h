#ifndef __STRUCT_TO_BYTES
#define __STRUCT_TO_BYTES

#include "all_def.h"

// for pk_IDP
struct public_key_IDP* pk_IDP_from_bytes(unsigned char* data_buffer);
int comapre_pk_IDP(struct public_key_IDP* pk_IDP, struct public_key_IDP* new_pk_IDP);
struct sigma_c* sigma_c_from_bytes(char* data_buffer, int length, struct public_key_IDP* pk_IDP);
#endif
