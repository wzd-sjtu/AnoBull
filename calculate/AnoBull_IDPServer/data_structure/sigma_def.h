#ifndef __SIGMA_H
#define __SIGMA_H

#include "/usr/local/include/pbc/pbc.h"
#include "/usr/local/include/pbc/pbc_test.h"

struct sigma {
    // G1
    element_t A_plus;
    // G1
    element_t A_ba;

    // G1
    element_t d;

    // R1 and R2 also in G1

    // c should be in some other region
    // Z_p  这个区域写错了
    element_t c;
    
    // Z_p
    element_t z_x;
    element_t z_r;
    element_t z_alpha;
    element_t z_beta;

    element_t* z_i_hidden;

    //////// 重要的中间变量，连乘上套了一个r次方 ////////
    // element_t middle_res;
};

// 也是需要一个最基本的希望存储的sigma，从而用于后续的整体程序处理
// struct stored_sigma;

#endif