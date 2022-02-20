#include "test.h"


int verify_sigma_c_equation_1(struct sigma_c* sigma_c_specific, struct public_key_IDP* pk_IDP) {
    struct sigma_c* signature_c = sigma_c_specific;
    
    // Client验证此签名是否成立？
    element_t temp1, temp2;
    element_init_GT(temp1, *pk_IDP->pair);
    element_init_GT(temp2, *pk_IDP->pair);

    element_t tmp;element_init_G2(tmp, *pk_IDP->pair);
    element_pow_zn(tmp, pk_IDP->g2, signature_c->x);
    element_mul(tmp, tmp, pk_IDP->omega);

    // 进行等式左边映射
    pairing_apply(temp1, signature_c->A,tmp, *pk_IDP->pair);

    // 进行等式右边映射
    pairing_apply(temp2, signature_c->middle_res, pk_IDP->g2, *pk_IDP->pair);

    if (!element_cmp(temp1, temp2)) {
        printf("signature_c equation 1 verifies\n");
    } else {
        printf("signature_c equation 1 does not verify\n");
    }

    return 1;
}

// this 函数是为了后文的底层函数来设计的

/*
int verify_A_and_A_plus(struct sigma* signature, struct public_key_IDP* pk_IDP) {
    element_init_G1(temp1, *pk_IDP->pair);

    // 涉及到了私钥，拒绝here的验证
    element_pow_zn(temp1, signature->A_plus, sk_IDP->gamma);

    if (!element_cmp(temp1, signature->A_ba)) {
        printf("A and A_ba equation 2 verifies\n");
    } else {
        printf("A and A_ba equation 2 does not verify\n");
    }
}
*/