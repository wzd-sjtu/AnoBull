#ifndef __SIGMA_C_DEF
#define __SIGMA_C_DEF

#include "/usr/local/include/pbc/pbc.h"
#include "/usr/local/include/pbc/pbc_test.h"

struct sigma_c {
    // Z_p
    element_t x;
    element_t s;
    // G_1
    element_t A;

    // G1  mid_res
    // h_0 h_1^m_i 连乘
    element_t middle_res;
};


#endif