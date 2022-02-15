#ifndef __TENANT_AUDIT_H
#define __TENANT_AUDIT_H

#include "IDP_init.h"

struct sigma_j {

    // 最好的办法还是链表+while循环，从而提升系统运行的速度
    
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

    element_t R2;
};

#endif