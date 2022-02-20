#ifndef __PUBLIC_KEY_DEF
#define __PUBLIC_KEY_DEF

#include "/usr/local/include/pbc/pbc.h"
#include "/usr/local/include/pbc/pbc_test.h"
#include "stdio.h"
#include "stdlib.h"
#include <string.h>
#include <openssl/sha.h>

// 公钥of IDP
// to some fixed space yes!
struct public_key_IDP {

    int total_num_of_h_i;

    // pair 是采用的群，是最重要的变量
    pairing_t* pair;

    // G2
    element_t omega;

    // G1
    element_t* h_vector;
    // G1
    element_t g1;
    // G2
    element_t g2;
};

#endif
