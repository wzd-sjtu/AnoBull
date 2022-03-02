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
struct secret_key_IDP* init_IDP_secret_key(pairing_t* pairing);
struct public_key_IDP* init_IDP_public_key(pairing_t* pairing, int N, struct secret_key_IDP* sk_IDP);

// IDP获得用户信息，进行解码
int is_hidden(char* select_vector, int loc);
void hash_SHA256(unsigned char* data_buffer, int length, unsigned char result[]);
struct sigma_c* compute_sigma_c(element_t* m_vector, struct public_key_IDP* pk_IDP, \
 struct secret_key_IDP* sk_IDP);

element_t* convert_info_to_vector(struct list* user_info_list_specific, struct public_key_IDP* pk_IDP);

// element_t* get_the_m_vector_and_selector_vector(char* data_buffer, struct public_key_IDP* pk_IDP);
struct m_vector_and_selector_struct* get_the_m_vector_and_selector_vector(char* data_buffer, struct public_key_IDP* pk_IDP);
// 同时最好也直接获取别的information
char* get_selector_vector(element_t* m_vector, struct public_key_IDP* pk_IDP);

// 对签名的合理性进行验证
int RP_verify(struct sigma* signature, element_t* m_vector, char* select_vector, \
    struct public_key_IDP* pk_IDP);
#endif