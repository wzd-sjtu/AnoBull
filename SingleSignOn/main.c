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

struct m_i_node {
    int index;
    struct m_i_node* next;
    element_t m_i;
};

// 公钥of IDP
// to some fixed space yes!
struct public_key_IDP {
    element_t omega;
    // 为了兼容，可以暂时留着它
    struct h_i_node* virtual_head;
    element_t* h_vector;

    int total_num_of_h_i;
    pairing_t* pair;
    element_t g1;
    element_t g2;
};

struct secret_key_IDP {
    element_t gamma;
};

struct sigma_c {
    // Z_p
    element_t x;
    element_t s;
    // G_1
    element_t A;
};

struct sigma {
    element_t A_plus;
    element_t A_ba;

    element_t d;
    element_t c;
    
    element_t z_x;
    element_t z_r;
    element_t z_appha;
    element_t z_beta;

    element_t* z_i_hidden;
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

    element_t gamma;
    element_init_Zr(gamma, *pairing);
    element_init_Zr(tmp->gamma, *pairing);

    // 生成随机私钥
    element_random(gamma);

    // tmp->gamma = gamma equation is always ok.
    element_set(tmp->gamma, gamma);

    return tmp;
}

// 链表版本，舍弃之
struct public_key_IDP* del_init_IDP_public_key(pairing_t* pairing, int N, struct secret_key_IDP* sk_IDP) {
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

    
    //pk_IDP->g1 = g1;
    //pk_IDP->g2 = g2;
    //pk_IDP->pair = pairing;
    element_set(pk_IDP->g1, g1);
    element_set(pk_IDP->g2, g2);
    pk_IDP->pair = pairing;

    // 数值赋值，为公钥做计算准备
    element_t* gamma = &sk_IDP->gamma;
    // ==
    element_t omega;
    element_init_G2(omega, *pairing);
    element_pow_zn(omega, g2, *gamma);

    element_set(pk_IDP->omega, omega); // 内容赋值, pk_IDP->omega = omega;

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
        element_init_G1(tmp_node->h_i, *pairing);
        
        element_t h_self;
        element_init_G1(h_self, *pairing);
        element_random(h_self);
        // tmp_node->h_i = h_self;
        element_set(h_self, tmp_node->h_i);
    }
    // init of pair and public key of IDP.

    return pk_IDP;
}

// 链表版本不好，不如使用数组版本，加上固定的类型转换
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

    
    //pk_IDP->g1 = g1;
    //pk_IDP->g2 = g2;
    //pk_IDP->pair = pairing;
    element_set(pk_IDP->g1, g1);
    element_set(pk_IDP->g2, g2);
    pk_IDP->pair = pairing;

    // 数值赋值，为公钥做计算准备
    element_t* gamma = &sk_IDP->gamma;
    // ==
    element_t omega;
    element_init_G2(omega, *pairing);
    element_pow_zn(omega, g2, *gamma);

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

    return pk_IDP;
}

// 链表版本，忽略
struct m_i_node* del_get_user_info(int N, pairing_t* pairing) {
    
    struct m_i_node* user_virtual_head = (struct m_i_node*)malloc(sizeof(struct m_i_node));
    memset(user_virtual_head, 0, sizeof(struct m_i_node));
    user_virtual_head->index = -1;
    user_virtual_head->next = NULL;

    struct m_i_node* m_i = user_virtual_head;
    
    for(int i=0; i<N; i++) {
        m_i->next = (struct m_i_node*)malloc(sizeof(struct m_i_node));

        m_i = m_i->next;
        memset(m_i, 0, sizeof(struct m_i_node));
        m_i->index = i+1;
        m_i->next = NULL;

        element_init_Zr(m_i->m_i, *pairing);
        element_random(m_i->m_i);
    }

    return user_virtual_head;
}

struct sigma_c* compute_sigma_c(element_t* m_vector, struct public_key_IDP* pk_IDP, struct secret_key_IDP* sk_IDP) {
    // 计算初始颁发的匿名凭证
    struct sigma_c* sc = (struct sigma_c*)malloc(sizeof(struct sigma_c));
    memset(sc, 0, sizeof(struct sigma_c));

    element_init_Zr(sc->x, *pk_IDP->pair);element_random(sc->x);
    element_init_Zr(sc->s, *pk_IDP->pair);element_random(sc->s);
    element_init_G1(sc->A, *pk_IDP->pair);

    // 计算A
    element_t res;
    element_init_G1(res, *pk_IDP->pair);

    // 涉及到一系列参数的计算，大部分是连乘
    // element_mul(element_t n, element_t a, element_t b) n=ab
    // element_pow_zn(element_t x, element_t a, element_t n) x=a^n

    element_t parcel;
    element_init_G1(parcel, *pk_IDP->pair);

    element_pow_zn(parcel, pk_IDP->h_vector[0], sc->s);
    element_set(res, parcel);

    int N = pk_IDP->total_num_of_h_i;
    for(int i=1; i<N; i++) {
        element_pow_zn(parcel, pk_IDP->h_vector[i], m_vector[i]);
        element_mul(res, res, parcel);
    }

    element_mul(res, res, pk_IDP->g1);

    element_t exponent_res;
    element_init_Zr(exponent_res, *pk_IDP->pair);
    element_add(exponent_res, sk_IDP->gamma, sc->x);

    element_t one_expo;
    element_init_Zr(one_expo, *pk_IDP->pair);

    // void element_div(element_t n, element_t a, element_t b)
    element_div(exponent_res, one_expo, exponent_res);

    // 最后再做指数运算
    element_pow_zn(res, res, exponent_res);

    element_set(sc->A, res);

    return sc;
}
// compile code:
// gcc main.c -L. -lpbc -lgmp -lcrypto

// 查看此index是否在被选择之列表
int is_hidden(char* select_vector, int loc) {
    return (select_vector[loc]&0x01)==1;
}

struct sigma* compute_sigma {
    sigma* sig = (sigma*)malloc(sizeof(sigma));
    memset(sig, 0, sizeof(sigma));

    

    return sig;
}
int main() {

    char* name = "D224";
    pairing_t* pair_use;
    pair_use = init_space(name); // it is always a pointer

    // 生成IDP私钥
    struct secret_key_IDP* sk_IDP = NULL;
    sk_IDP = init_IDP_secret_key(pair_use);

    // 生成IDP公钥，需要一个参数N
    int N = 32;
    struct public_key_IDP* pk_IDP = NULL;
    pk_IDP = init_IDP_public_key(pair_use, N, sk_IDP);

    // 存成链表速度比较慢，最好用数组
    // 先写一个初始版本出来，再说怎样优化
    // there should be only N-1 useful information for everyone of us

    // 获取了多个信息，information，需要进行匹配时，要如何处理呢？不明白。。
    // 可以用二进制序列来加速处理逻辑

    // struct m_i_node* user_virtual_head = get_user_info(N-1, pair_use);
    // 用户信息初始化

    element_t* m_vector = (element_t*)malloc(N*sizeof(element_t));
    for(int i=1; i<N; i++) {
        element_init_Zr(m_vector[i], *pair_use);
        element_random(m_vector[i]);
    }

    // 计算初始签名 sigma_c
    struct sigma_c* sigma_c_user = compute_sigma_c(m_vector, pk_IDP, sk_IDP);

    // successfully完成了初始版本的签名，令人费解？
    // 用户消息一定是N个吗？这是以后才需要考虑的问题

    // 用户收到公钥pk_IDP和签名sigma_c，下面计算自己的个性化签名
    // 浪费一点空间，生成需求和不需求序列
    char* select_vector = (char*)malloc(N*sizeof(char));
    memset(select_vector, 0, N*sizeof(char)); // 是否要全部刷0？有时是无必要的
    
    select_vector[4] = 1;
    select_vector[7] = 1;
    select_vector[30] = 1;

    // 完成complete？

    if(pk_IDP!=NULL) printf("\n successfully! \n");

    return 0;
}