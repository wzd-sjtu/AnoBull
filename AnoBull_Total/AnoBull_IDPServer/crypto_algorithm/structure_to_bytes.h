#ifndef __STRUCT_TO_BYTES
#define __STRUCT_TO_BYTES

#include "basic_algorithm.h"
#include "all_def.h"

// for pk_IDP
int pk_IDP_to_bytes(char* thread_send_buffer, int data_len_limit);
struct public_key_IDP* pk_IDP_from_bytes(unsigned char* data_buffer, int length);
int comapre_pk_IDP(struct public_key_IDP* new_pk_IDP);

int sigma_c_to_bytes(struct sigma_c* will_send_sigma_c, char* data_buffer, int data_len_limit);
struct sigma_c* sigma_c_from_bytes(char* data_buffer, int length, struct public_key_IDP* pk_IDP);

struct sigma* sigma_from_bytes(char* data_buffer, int length, struct public_key_IDP* pk_IDP, char** m_vector_point);

// 再一次需要插入取出部分数据库的重要条目的了。
// 全部转换为缓存char
int sigma_store_to_bytes(struct sigma_store* will_send_sigma, char* data_buffer, int data_len_limit, struct public_key_IDP* pk_IDP);
struct sigma_store* sigma_store_from_bytes(char* data_buffer, int length, struct public_key_IDP* pk_IDP, char** m_vector_point);

// 数据库需要对这些info进行存储操作
// 需要在compute中，完成对sigma_store的存储

#endif
