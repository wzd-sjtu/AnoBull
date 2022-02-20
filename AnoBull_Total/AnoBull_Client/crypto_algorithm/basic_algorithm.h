#ifndef __BASIC_ALGORITHM
#define __BASIC_ALGORITHM

#include "/usr/local/include/pbc/pbc.h"
#include "/usr/local/include/pbc/pbc_test.h"
#include "stdio.h"
#include "stdlib.h"
#include <string.h>
#include <openssl/sha.h>

#include "all_def.h"

// 这里需要加一个配置数据结构接口
pairing_t* init_space(char* curve_name);

// IDP获得用户信息，进行解码
int is_hidden(char* select_vector, int loc);

element_t* convert_info_to_vector(struct list* user_info_list_specific, struct public_key_IDP* pk_IDP);

struct sigma* compute_sigma(struct sigma_c* signature_c, struct public_key_IDP* pk_IDP, \
    element_t* m_vector, char* select_vector);

int RP_verify(struct sigma* signature, element_t* m_vector, char* select_vector, \
    struct public_key_IDP* pk_IDP);
#endif