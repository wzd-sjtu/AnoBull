#include "/usr/local/include/pbc/pbc.h"
#include "/usr/local/include/pbc/pbc_test.h"
#include "stdio.h"
#include "stdlib.h"
#include <string.h>
#include <openssl/sha.h>

// describe the chain
struct h_i_node {
    int index;
    struct h_i_node* next;
    element_t h_i;
};

// 公钥of IDP
// to some fixed space yes!
struct public_key_IDP {
    element_t omega;
    struct h_i_node* virtual_head;
    int total_num_of_h_i;
    pairing_t* pair;
    element_t g1;
    element_t g2;
};
struct secret_key_IDP {
    element_t gamma;
};


char D224_param[1347] = "type d \
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

pairing_t* init_space(char* curve_name) {
    if(strcmp(curve_name, "D224") == 0) {
        size_t count = strlen(D224_param);
        // printf("%d\n", count);
        // 经测试，d224椭圆曲线参数数组大小为1346，故将大小初始化为1347byte，即为char param[1347]

        // pointer总是需要初始化一下
        pairing_t* tmp = malloc(sizeof(pairing_t));
        pairing_init_set_buf(*tmp, D224_param, count);
        return tmp;
    }
    return NULL;
}

// 在init开始之前，就要完成基本的malloc了
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

    // element of g1 and g2
    element_t g1;
    element_t g2;
    element_init_G1(g1, *pairing);
    element_init_G2(g2, *pairing);
    element_random(g1);
    element_random(g2);

    
    //pk_IDP->g1 = g1;
    //pk_IDP->g2 = g2;
    //pk_IDP->pair = pairing;
    element_set(g1, pk_IDP->g1);
    element_set(g2, pk_IDP->g2);
    pk_IDP->pair = pairing;

    // 数值赋值，为公钥做计算准备
    element_t* gamma = &sk_IDP->gamma;
    // ==
    element_t omega;
    element_init_G2(omega, *pairing);
    element_pow_zn(omega, g2, *gamma);
    element_set(omega, pk_IDP->omega); // 内容赋值，背后的内容的复制+粘贴

    // total num calculate and compute
    pk_IDP->total_num_of_h_i = N;

    // h_i_node init
    struct h_i_node* virtual_head = (struct h_i_node*)malloc(sizeof(struct h_i_node));
    memset(virtual_head, 0, sizeof(struct h_i_node));
    virtual_head->index = -1;
    virtual_head->next = NULL;

    pk_IDP->virtual_head = virtual_head;

    struct h_i_node* tmp_node = virtual_head;

    for(int i=0; i<N; i++) {
        tmp_node->next = (struct h_i_node*)malloc(sizeof(struct h_i_node));
        memset(tmp_node->next, 0, sizeof(struct h_i_node));

        tmp_node = tmp_node->next; // point to itself
        
        // 为了加速，可以存一个hash表
        tmp_node->index = i; // node number
        tmp_node->next = NULL;
        
        element_t h_self;
        element_init_G1(h_self, *pairing);
        element_random(h_self);

        // tmp_node->h_i = h_self;
        element_set(h_self, tmp_node->h_i);
    }

    // init of pair and public key of IDP.
    return pk_IDP;
}

// compile code:
// gcc main.c -L. -lpbc -lgmp -lcrypto
int main() {

    char* name = "D224";
    pairing_t* pair_use;
    pair_use = init_space(name); // it is always a pointer

    // 生成IDP私钥
    struct secret_key_IDP* sk_IDP;
    sk_IDP = init_IDP_secret_key(pair_use);

    // 生成IDP公钥，需要一个参数N
    int N = 32;
    struct public_key_IDP* pk_IDP;
    // all use key to exchange things
    pk_IDP = init_IDP_public_key(pair_use, N, sk_IDP);

    if(pair_use!=NULL) printf("\n successfully! \n");

    return 0;
}