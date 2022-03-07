#ifndef __SIGMA_STORE_DEF_H
#define __SIGMA_STORE_DEF_H

// 本数据结构专门用于定义存储在数据库中的sigma
// 这个是为了租户tenant进行audit验证而加入的数据结构

struct sigma_store {
    // 每次运算之前，都需要存储一下
    // 为后文的处理打下基础
    // G1
    element_t A_plus;
    // G1
    element_t A_ba;

    // G1
    element_t d;

    // R1 and R2 also in G1
    element_t R2;
    // c should be in some other region
    // Z_p  这个区域写错了
    element_t c;
    
    // Z_p
    element_t z_x;
    element_t z_r;
    element_t z_alpha;
    element_t z_beta;

    // 这个z也全都要存储的
    element_t* z_i_hidden;
};

#endif