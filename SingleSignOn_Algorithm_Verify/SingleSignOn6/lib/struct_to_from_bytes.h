#ifndef __LIB_STRUCT_TO_FROM_HASH
#define __LIB_STRUCT_TO_FROM_HASH

#include "CLIENT_compute.h"
#include "IDP_audit.h"
#include "IDP_init.h"

// for pk_IDP
unsigned char* pk_IDP_to_bytes(struct public_key_IDP* pk_IDP);
struct public_key_IDP* pk_IDP_from_bytes(unsigned char* data_buffer);
int comapre_pk_IDP(struct public_key_IDP* pk_IDP, struct public_key_IDP* new_pk_IDP);

#endif