#ifndef __SIGMA_DEF_H
#define __SIGMA_DEF_H

struct sigma {
    // G1
    element_t A_plus;
    // G1
    element_t A_ba;

    // G1
    element_t d;

    // R1 and R2 also in G1

    // Z_p
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


#endif