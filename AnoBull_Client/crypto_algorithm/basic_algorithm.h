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
 

#endif