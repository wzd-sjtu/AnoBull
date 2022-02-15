#ifndef __IDP_IDP_AUDIT_H
#define __IDP_IDP_AUDIT_H

#include "IDP_init.h"

struct sigma_j {
    // G1
    element_t A_plus;
    // G1
    element_t A_ba;

    // G1
    element_t d;

    // R1 and R2 also in G1
    // c还是取到Z_p中比较合理？
    element_t c;
    
    // Z_p
    element_t z_x;
    element_t z_r;
    element_t z_alpha;
    element_t z_beta;

    // how to reuse it? I tmply have no idea, should be not pointer
    element_t* z_i_hidden;

    element_t R2;
    // 缓存起来，用于加速
    // 最好保存为全局变量？
    //////// 重要的中间变量，连乘上套了一个r次方 ////////
    // 此处不需要middle_res
    // element_t middle_res;

};

#endif