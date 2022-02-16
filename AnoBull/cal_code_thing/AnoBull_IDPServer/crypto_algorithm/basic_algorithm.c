#include "/usr/local/include/pbc/pbc.h"
#include "/usr/local/include/pbc/pbc_test.h"
#include "stdio.h"
#include "stdlib.h"
#include <string.h>
#include <openssl/sha.h>

#include "basic_algorithm.h"

// 全局静态变量
static char D224_param[1347] = "type d \
q 15028799613985034465755506450771565229282832217860390155996483840017 \
n 15028799613985034465755506450771561352583254744125520639296541195021 \
h 1 \
r 15028799613985034465755506450771561352583254744125520639296541195021 \
a 1871224163624666631860092489128939059944978347142292177323825642096 \
b 9795501723343380547144152006776653149306466138012730640114125605701 \
k 6 \
nk 11522474695025217370062603013790980334538096429455689114222024912184432319228393204650383661781864806076247259556378350541669994344878430136202714945761488385890619925553457668158504202786580559970945936657636855346713598888067516214634859330554634505767198415857150479345944721710356274047707536156296215573412763735135600953865419000398920292535215757291539307525639675204597938919504807427238735811520 \
hk 51014915936684265604900487195256160848193571244274648855332475661658304506316301006112887177277345010864012988127829655449256424871024500368597989462373813062189274150916552689262852603254011248502356041206544262755481779137398040376281542938513970473990787064615734720 \
coeff0 11975189258259697166257037825227536931446707944682470951111859446192 \
coeff1 13433042200347934827742738095249546804006687562088254057411901362771 \
coeff2 8327464521117791238079105175448122006759863625508043495770887411614 \
nqr 142721363302176037340346936780070353538541593770301992936740616924";

// 均是在运行中生成，堆空间应该是很大才对
pairing_t* init_space(char* curve_name) {
    if(strcmp(curve_name, "D224") == 0) {
        size_t count = strlen(D224_param);

        pairing_t* tmp = malloc(sizeof(pairing_t));
        pairing_init_set_buf(*tmp, D224_param, count);
        return tmp;
    }
    return NULL;
}


struct secret_key_IDP* init_IDP_secret_key(pairing_t* pairing) {
    struct secret_key_IDP* tmp = (struct secret_key_IDP*)malloc(sizeof(struct secret_key_IDP));
    memset(tmp, 0, sizeof(struct secret_key_IDP));
    element_init_Zr(tmp->gamma, *pairing);
    // 生成随机私钥
    element_random(tmp->gamma);
    return tmp;
}
struct public_key_IDP* init_IDP_public_key(pairing_t* pairing, int N, struct secret_key_IDP* sk_IDP) {
    struct public_key_IDP* pk_IDP = (struct public_key_IDP*)malloc(sizeof(struct public_key_IDP));
    memset(pk_IDP, 0, sizeof(struct public_key_IDP));

    // 需要提前初始化
    element_init_G1(pk_IDP->g1, *pairing);
    element_init_G2(pk_IDP->g2, *pairing);
    element_init_G2(pk_IDP->omega, *pairing);
    
    // element of g1 and g2
    element_t g1;
    element_t g2;
    element_init_G1(g1, *pairing);
    element_init_G2(g2, *pairing);
    element_random(g1);
    element_random(g2);


    element_set(pk_IDP->g1, g1);
    element_set(pk_IDP->g2, g2);
    
    // 指针指向固定的一个元素
    pk_IDP->pair = pairing;

    // 数值赋值，为公钥做计算准备
    // element_t* gamma = &sk_IDP->gamma;
    // ==
    element_t omega;
    element_init_G2(omega, *pairing);
    element_pow_zn(omega, g2, sk_IDP->gamma);

    element_set(pk_IDP->omega, omega); // 内容赋值, pk_IDP->omega = omega;

    // total num calculate and compute
    pk_IDP->total_num_of_h_i = N;

    // h_i_node init
    // use h_vector to simplify the code
    pk_IDP->h_vector = (element_t*)malloc(N*sizeof(element_t));
    for(int i=0; i<N; i++) {
        element_init_G1(pk_IDP->h_vector[i], *pairing);
        element_random(pk_IDP->h_vector[i]);
    }

    element_clear(g1);
    element_clear(g2);
    element_clear(omega);

    return pk_IDP;
}
// 查看此index是否在被选择之列表
int is_hidden(char* select_vector, int loc) {
     if((select_vector[loc]&0x01)==1) {
         return 1;
     }
     else return 0;
}

/*
void hash_SHA256(unsigned char* data_buffer, int length, unsigned char result[]) {
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, data_buffer, length);

    SHA256_Final(result, &sha256_ctx);
    return;
}
*/
struct sigma_c* compute_sigma_c(element_t* m_vector, struct public_key_IDP* pk_IDP, \
 struct secret_key_IDP* sk_IDP) {
    // 计算初始颁发的匿名凭证
    struct sigma_c* signature_c = (struct sigma_c*)malloc(sizeof(struct sigma_c));
    memset(signature_c, 0, sizeof(struct sigma_c));

    element_init_Zr(signature_c->x, *pk_IDP->pair);
    element_random(signature_c->x);
    element_init_Zr(signature_c->s, *pk_IDP->pair);
    element_random(signature_c->s);
    element_init_G1(signature_c->A, *pk_IDP->pair);

    // 计算A
    element_t res;
    element_init_G1(res, *pk_IDP->pair);

    element_t parcel;
    element_init_G1(parcel, *pk_IDP->pair);

    element_pow_zn(parcel, pk_IDP->h_vector[0], signature_c->s);
    element_set(res, parcel);

    int N = pk_IDP->total_num_of_h_i;
    for(int i=1; i<N; i++) {
        element_pow_zn(parcel, pk_IDP->h_vector[i], m_vector[i]);
        element_mul(res, res, parcel);
    }

    element_mul(res, res, pk_IDP->g1);

    //////// 此时计算得到了重要的中间连乘，可以作为有效的中间变量 ////////
    element_init_G1(signature_c->middle_res, *pk_IDP->pair);
    element_set(signature_c->middle_res, res);


    // 处理计算A需要的指数
    element_t exponent_res;
    element_init_Zr(exponent_res, *pk_IDP->pair);
    element_add(exponent_res, sk_IDP->gamma, signature_c->x);

    element_t one_expo;
    element_init_Zr(one_expo, *pk_IDP->pair);
    element_set1(one_expo); // 做经典的除法

    // void element_div(element_t n, element_t a, element_t b)
    element_div(exponent_res, one_expo, exponent_res);

    // 最后再做指数运算
    element_pow_zn(res, res, exponent_res);

    element_set(signature_c->A, res);

    element_clear(res);
    element_clear(parcel);
    element_clear(exponent_res);
    element_clear(one_expo);

    return signature_c;
}