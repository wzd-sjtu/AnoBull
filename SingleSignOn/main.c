#include "/usr/local/include/pbc/pbc.h"
#include "/usr/local/include/pbc/pbc_test.h"
#include "stdio.h"
#include "stdlib.h"
#include <string.h>
#include <openssl/sha.h>

//////////////////////////////  程序重要前提，h从0开始下标，m从1开始下标 //////////////////////


// designature_cribe the chain
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
    // G2
    element_t omega;
    // 为了兼容，可以暂时留着它
    struct h_i_node* virtual_head;
    // 所有的h_i均来自群G1
    // G1
    element_t* h_vector;

    int total_num_of_h_i;
    pairing_t* pair;
    // G1
    element_t g1;
    // G2
    element_t g2;
};

struct secret_key_IDP {
    // Z_p
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
    // G1
    element_t A_plus;
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

    element_t* z_i_hidden;

    // 缓存起来，用于加速
    // 最好保存为全局变量？
    //////// 重要的中间变量，连乘上套了一个r次方 ////////

    element_t middle_res;
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
        // 总是要malloc一下的了
        pairing_t* tmp = malloc(sizeof(pairing_t));
        pairing_init_set_buf(*tmp, D224_param, count);
        return tmp;
    }
    return NULL;
}

// 在init开始之前，就要完成基本的malloc了
struct secret_key_IDP* init_IDP_secret_key(pairing_t* pairing) {
    struct secret_key_IDP* tmp = (struct secret_key_IDP*)malloc(sizeof(struct secret_key_IDP));
    
    // 是否需要刷0？需要的
    memset(tmp, 0, sizeof(struct secret_key_IDP));

    element_t gamma;
    element_init_Zr(gamma, *pairing);
    element_init_Zr(tmp->gamma, *pairing);

    // 生成随机私钥
    element_random(gamma);

    // tmp->gamma = gamma equation is always ok.
    element_set(tmp->gamma, gamma);

    element_clear(gamma);
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


    element_set(pk_IDP->g1, g1);
    element_set(pk_IDP->g2, g2);
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

struct sigma_c* compute_sigma_c(element_t* m_vector, struct public_key_IDP* pk_IDP, \
 struct secret_key_IDP* sk_IDP) {
    // 计算初始颁发的匿名凭证
    struct sigma_c* signature_c = (struct sigma_c*)malloc(sizeof(struct sigma_c));
    memset(signature_c, 0, sizeof(struct sigma_c));

    element_init_Zr(signature_c->x, *pk_IDP->pair);element_random(signature_c->x);
    element_init_Zr(signature_c->s, *pk_IDP->pair);element_random(signature_c->s);
    element_init_G1(signature_c->A, *pk_IDP->pair);

    // 计算A
    element_t res;
    element_init_G1(res, *pk_IDP->pair);

    // 涉及到一系列参数的计算，大部分是连乘
    // element_mul(element_t n, element_t a, element_t b) n=ab
    // element_pow_zn(element_t x, element_t a, element_t n) x=a^n

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
// compile code:
// gcc main.c -L. -lpbc -lgmp -lcrypto

// 查看此index是否在被选择之列表
int is_hidden(char* select_vector, int loc) {
     if((select_vector[loc]&0x01)==1) {
         return 1;
     }
     else return 0;
}

void hash_SHA256(unsigned char* data_buffer, int length, unsigned char result[]) {
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, data_buffer, length);

    SHA256_Final(result, &sha256_ctx);
    return;
}
struct sigma* compute_sigma(struct sigma_c* signature_c, struct public_key_IDP* pk_IDP,
    element_t* m_vector, char* select_vector) {

    struct sigma* signature = (struct sigma*)malloc(sizeof(struct sigma));
    memset(signature, 0, sizeof(struct sigma));

    // 生成此处对应的签名。

    element_t r;
    element_t r_plus;
    element_init_Zr(r, *pk_IDP->pair);
    element_init_Zr(r_plus, *pk_IDP->pair);
    element_random(r);
    element_random(r_plus);

    
    // A_plus \in G1  
    // A_ba \in G1
    element_init_G1(signature->A_plus, *pk_IDP->pair);
    element_init_G1(signature->A_ba, *pk_IDP->pair);

    // 计算A_plus
    element_pow_zn(signature->A_plus, signature_c->A, r);

    // 计算A_ba
    //////// 首先计算中间变量，即那个一群连乘 ////////
    element_t res;
    element_init_G1(res, *pk_IDP->pair);

    // 涉及到一系列参数的计算，大部分是连乘
    // element_mul(element_t n, element_t a, element_t b) n=ab
    // element_pow_zn(element_t x, element_t a, element_t n) x=a^n

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

    element_init_G1(signature->middle_res, *pk_IDP->pair);
    // middle res包括 g1 h_0^s parcel式子
    element_set(signature->middle_res, res);
    //////// 重要的中间变量，连乘上套了一个r次方 ////////
    element_pow_zn(signature->middle_res, signature->middle_res, r);

    //////// 计算A_ba的下一步骤 ////////

    element_set(res, signature->A_plus);
    element_set(parcel, signature_c->x);
    element_neg(parcel, parcel); // -x
    element_pow_zn(res, res, parcel);
    
    element_mul(signature->A_ba, res, signature->middle_res);


    
    // 下面计算d
    element_init_G1(signature->d, *pk_IDP->pair);
    element_pow_zn(res, pk_IDP->h_vector[0], r_plus);
    element_mul(signature->d, signature->middle_res, res);

    // 可以试着验证一下下等式
    //////// A_ba = (A')^\gamma ////////

    // 又选取了一大堆变量，用于后文的计算
    element_t r_x;
    element_t r_r;
    element_t r_alpha;
    element_t r_beta;
    element_t* r_var = (element_t*)malloc(N*sizeof(element_t));

    element_init_Zr(r_x, *pk_IDP->pair);
    element_random(r_x);
    element_init_Zr(r_r, *pk_IDP->pair);
    element_random(r_r);
    element_init_Zr(r_alpha, *pk_IDP->pair);
    element_random(r_alpha);
    element_init_Zr(r_beta, *pk_IDP->pair);
    element_random(r_beta);

    for(int i=0; i<N; i++) {
        element_init_Zr(r_var[i], *pk_IDP->pair);
        element_random(r_var[i]);
    }

    element_t R1;element_init_G1(R1, *pk_IDP->pair);
    element_t R2;element_init_G1(R2, *pk_IDP->pair);

    
    // 计算R1  res与parcel均为G1群
    // 下文需要改换R1的群

    element_clear(res);
    element_init_Zr(res, *pk_IDP->pair);
    element_clear(parcel);
    element_init_G1(parcel, *pk_IDP->pair);

    element_set(res, r_x);
    element_neg(res, res); // -r_x
    element_pow_zn(parcel, signature->A_plus, res);
    element_set(R1, parcel);

    element_set(res, r_r);
    element_pow_zn(parcel, pk_IDP->h_vector[0], res);
    element_mul(R1, parcel, R1); // 自己乘自己

    // 计算R2
    element_set(res, r_alpha);
    element_pow_zn(parcel, signature->d, res);
    element_set(R2, parcel);

    element_set(res, r_beta);
    element_neg(res, res);
    element_pow_zn(parcel, pk_IDP->h_vector[0], res);
    element_mul(R2, R2, parcel);

    // 出现了many bugs，群的域弄不清楚了
    
    element_set1(parcel);
    element_t mid_tmp;element_init_G1(mid_tmp, *pk_IDP->pair);
    // 此处i可以从0开始，对的
    for(int i=0; i<N; i++) {
        // 如果是被隐藏的内容
        if(is_hidden(select_vector, i)) {
            // parcel是前面声明过得中间变量
            element_pow_zn(mid_tmp, pk_IDP->h_vector[i], r_var[i]);
            element_mul(parcel, parcel, mid_tmp);
        }
    }

    // 32
    // how to compute the H? I have no idea.

    element_mul(R2, R2, parcel);


    
    // parcel G1    res Z_r  mid_tmp G1
    // 计算 alpha 和 beta
    element_t alpha;
    element_t beta;
    element_init_Zr(alpha, *pk_IDP->pair);
    element_init_Zr(beta, *pk_IDP->pair);

    //// 取逆 ////
    element_invert(alpha, r);
    element_mul(beta, alpha, r_plus);
    element_add(beta, beta, signature_c->s);

    // 计算c，也就是hash对
    // hash函数，仅仅适用于此处？对的了呢

    // 进行了具体的底层byte安排
    // 以下是Hash的过程

    
    int H_length = 0;
    int A_plus_length = 0, A_ba_length = 0, d_length = 0, R1_length = 0, R2_length = 0;

    A_plus_length = element_length_in_bytes(signature->A_plus);
    A_ba_length = element_length_in_bytes(signature->A_ba);
    d_length = element_length_in_bytes(signature->d);
    R1_length = element_length_in_bytes(R1);
    R2_length = element_length_in_bytes(R2);

    H_length = A_plus_length + A_ba_length + R1_length + R2_length;

    unsigned char* data_buffer = (unsigned char*)malloc(H_length*sizeof(unsigned char));
    memset(data_buffer, 0, H_length*sizeof(unsigned char));
    // 最后没有必要补\0

    unsigned char* tmp_buffer = data_buffer;
    element_to_bytes(tmp_buffer, signature->A_plus);
    tmp_buffer += A_plus_length;
    element_to_bytes(tmp_buffer, signature->A_ba);
    tmp_buffer += A_ba_length;
    element_to_bytes(tmp_buffer, signature->d);
    tmp_buffer += d_length;
    element_to_bytes(tmp_buffer, R1);
    tmp_buffer += R1_length;
    element_to_bytes(tmp_buffer, R2);
    // tmp_buffer += R2_length;

    // void hash_SHA256(unsigned char* data_buffer, int length, unsigned char result[])
    unsigned char result[32] = {0};
    hash_SHA256(data_buffer, H_length, result);
    // printf(result);
    // 成功得到暂时的结果，需要反向映射回去
    element_init_Zr(signature->c, *pk_IDP->pair);

    //////////// 重要的哈希函数位置  写注释提醒自己 ////////////
    element_from_hash(signature->c, result, 32); // sha256's length is always 32

    
    // 计算z_...
    // 可以不对z做初始化，编译也可以通过？
    // z_x
    element_init_Zr(signature->z_x, *pk_IDP->pair);
    element_mul(signature->z_x, signature->c, signature_c->x);
    element_add(signature->z_x, signature->z_x, r_x);
    // z_r
    element_init_Zr(signature->z_r, *pk_IDP->pair);
    element_mul(signature->z_r, signature->c, r_r);
    element_add(signature->z_r, signature->z_r, r_plus);
    // z_alpha
    element_init_Zr(signature->z_alpha, *pk_IDP->pair);
    element_mul(signature->z_alpha, signature->c, alpha);
    element_add(signature->z_alpha, signature->z_alpha, r_alpha);
    // z_beta
    element_init_Zr(signature->z_beta, *pk_IDP->pair);
    element_mul(signature->z_beta, signature->c, beta);
    element_add(signature->z_beta, signature->z_beta, r_beta);
    // z_i
    
     // 是否需要选择向量呢？暂时未知

    // 堆空间发生了溢出
    // 需要释放一切没必要的资源
    element_clear(R1);
    element_clear(R2);
    element_clear(r);
    element_clear(r_plus);

    element_clear(res);
    element_clear(parcel);
    element_clear(mid_tmp);

    element_clear(r_x);
    element_clear(r_r);
    element_clear(r_alpha);
    element_clear(r_beta);

    signature->z_i_hidden = (element_t *)malloc(N*sizeof(element_t));
    for(int i=0; i<N; i++) {
        // 不论如何，采用全部初始化的原则
        element_init_Zr(signature->z_i_hidden[i], *pk_IDP->pair);
        
        if(is_hidden(select_vector, i)) {
            // 如果是被隐藏的element，那么初始化并且赋值
            element_mul(signature->z_i_hidden[i], signature->c, m_vector[i]);
            element_add(signature->z_i_hidden[i], signature->z_i_hidden[i], r_var[i]);
        }
    }
    
    // 至此，signature完全结束，返回签名结果
    for(int i=0; i<N; i++) {
        element_clear(r_var[i]); // all clean is ok！
    }
    // 直接free即可
    free(r_var);
    return signature;
}


// RP_verify(signature, m_vector, select_vector, pk_IDP);

int RP_verify(struct sigma* signature, element_t* m_vector, char* select_vector,
    struct public_key_IDP* pk_IDP) {
    
    
    // 恢复出R1和R2
    element_t R1;element_init_G1(R1, *pk_IDP->pair);
    element_t R2;element_init_G1(R2, *pk_IDP->pair);

    element_t res;element_init_Zr(res, *pk_IDP->pair);
    element_t parcel;element_init_G1(parcel, *pk_IDP->pair);
    element_t res_in_G1;element_init_G1(res_in_G1, *pk_IDP->pair);

    
    // 恢复R1
    element_neg(res, signature->z_x);
    element_pow_zn(R1, signature->A_plus, res);

    element_pow_zn(res_in_G1, pk_IDP->h_vector[0], signature->z_r);
    element_mul(R1, R1, res_in_G1); // 将中间变量乘上去即可得之

    element_neg(res, signature->c);
    element_div(res_in_G1, signature->A_ba, signature->d);
    element_pow_zn(res_in_G1, res_in_G1, res);

    element_mul(R1, R1, res_in_G1);

    
    // 恢复R2
    
    // 首先要将R2存入适当的群内
    element_clear(res);
    element_init_G1(res, *pk_IDP->pair);

    element_set(res_in_G1, pk_IDP->g1);
    element_set1(res);
    for(int i=1; i<pk_IDP->total_num_of_h_i; i++) {
        if(!is_hidden(select_vector, i)) {
            element_pow_zn(parcel, pk_IDP->h_vector[i], m_vector[i]);
            element_mul(res, res, parcel);
        }
    }
    element_mul(res_in_G1, res_in_G1, res);

    element_clear(res);
    element_init_Zr(res, *pk_IDP->pair);
    
    element_neg(res, signature->c);
    element_pow_zn(res_in_G1, res_in_G1, res);

    element_set(R2, res_in_G1);

    element_neg(res, signature->z_beta);
    element_pow_zn(res_in_G1, pk_IDP->h_vector[0], res);
    element_mul(R2, R2, res_in_G1);
    
    element_pow_zn(res_in_G1, signature->d, signature->z_alpha);
    element_mul(R2, R2, res_in_G1);

    // 进入连乘周期
    element_clear(res);
    element_init_G1(res, *pk_IDP->pair);

    element_clear(parcel);
    element_init_Zr(res, *pk_IDP->pair);

    // res均设置为G1群，parcel设置为Zr群
    element_set1(res);
    for(int i=0; i<pk_IDP->total_num_of_h_i; i++) {
        if(is_hidden(select_vector, i)) {
            // printf("I am happy!\n");
            element_neg(parcel, signature->z_i_hidden[i]);
            element_pow_zn(res_in_G1, pk_IDP->h_vector[i], parcel);
            element_mul(res, res, res_in_G1);
        }
    }
    element_mul(R2, R2, res);

    // 完成R1与R2的恢复后，进行最终的验证环节：


    element_t temp1, temp2;
    element_init_GT(temp1, *pk_IDP->pair);
    element_init_GT(temp2, *pk_IDP->pair);

    pairing_apply(temp1, signature->A_ba, pk_IDP->g2, *pk_IDP->pair);
    pairing_apply(temp2, signature->A_plus, pk_IDP->omega, *pk_IDP->pair);
    if (!element_cmp(temp1, temp2)) {
        printf("equation 1 signature verifies\n");
    } else {
        printf("equation 1 signature does not verify\n");
    }


    // 恢复签名c
    int H_length = 0;
    int A_plus_length = 0, A_ba_length = 0, d_length = 0, R1_length = 0, R2_length = 0;

    A_plus_length = element_length_in_bytes(signature->A_plus);
    A_ba_length = element_length_in_bytes(signature->A_ba);
    d_length = element_length_in_bytes(signature->d);
    R1_length = element_length_in_bytes(R1);
    R2_length = element_length_in_bytes(R2);

    H_length = A_plus_length + A_ba_length + R1_length + R2_length;

    unsigned char* data_buffer = (unsigned char*)malloc(H_length*sizeof(unsigned char));
    memset(data_buffer, 0, H_length*sizeof(unsigned char));
    // 最后没有必要补\0

    unsigned char* tmp_buffer = data_buffer;
    element_to_bytes(tmp_buffer, signature->A_plus);
    tmp_buffer += A_plus_length;
    element_to_bytes(tmp_buffer, signature->A_ba);
    tmp_buffer += A_ba_length;
    element_to_bytes(tmp_buffer, signature->d);
    tmp_buffer += d_length;
    element_to_bytes(tmp_buffer, R1);
    tmp_buffer += R1_length;
    element_to_bytes(tmp_buffer, R2);
    // tmp_buffer += R2_length;

    // void hash_SHA256(unsigned char* data_buffer, int length, unsigned char result[])
    unsigned char result[32] = {0};
    hash_SHA256(data_buffer, H_length, result);
    // printf(result);
    // 成功得到暂时的结果，需要反向映射回去

    element_t c_reproduce;
    element_init_Zr(c_reproduce, *pk_IDP->pair);
    element_from_hash(c_reproduce, result, 32); // sha256's length is always 32

    if (!element_cmp(c_reproduce, signature->c)) {
        printf("equation 2 signature verifies\n");
    } else {
        printf("equation 2 signature does not verify\n");
    }
    // 至此完成整个算法过程的编写
    

    // 删除中间变量
    element_clear(R1);
    element_clear(R2);
    element_clear(res);
    element_clear(parcel);
    element_clear(res_in_G1);

    element_clear(R1);
    element_clear(R2);

    element_clear(temp1);
    element_clear(temp2);

    free(data_buffer);
    return 1;
}

void clear_all(struct public_key_IDP* pk_IDP, struct secret_key_IDP* sk_IDP, \
    struct sigma_c* signature_c, struct sigma* signature) {
    int N = pk_IDP->total_num_of_h_i;

    element_clear(pk_IDP->omega);
    for(int i=0; i<N; i++) {
        element_clear(pk_IDP->h_vector[i]);
    }
    free(pk_IDP->h_vector);
    pairing_clear(*pk_IDP->pair);
    element_clear(pk_IDP->g1);
    element_clear(pk_IDP->g2);

    element_clear(sk_IDP->gamma);

    /*
    element_clear(signature_c->x);
    element_clear(signature_c->s);
    element_clear(signature_c->A);

    element_clear(signature->A_plus);
    element_clear(signature->A_ba);
    element_clear(signature->d);
    element_clear(signature->c);
    element_clear(signature->z_x);
    element_clear(signature->z_r);
    element_clear(signature->z_alpha);
    element_clear(signature->z_beta);
    for(int i=0; i<N; i++) {
        element_clear(signature->z_i_hidden[i]);
    }
    free(signature->z_i_hidden);
    element_clear(signature->middle_res);
    */

    return;
}

void small_version_clear_all(struct public_key_IDP* pk_IDP, struct secret_key_IDP* sk_IDP, \
    struct sigma_c* signature_c, struct sigma* signature) {
    int N = pk_IDP->total_num_of_h_i;

    element_clear(pk_IDP->omega);
    for(int i=0; i<N; i++) {
        element_clear(pk_IDP->h_vector[i]);
    }
    free(pk_IDP->h_vector);
    pairing_clear(*pk_IDP->pair);
    element_clear(pk_IDP->g1);
    element_clear(pk_IDP->g2);
    element_clear(sk_IDP->gamma);

    
    element_clear(signature_c->x);
    element_clear(signature_c->s);
    element_clear(signature_c->A);

    
    element_clear(signature->A_plus);
    element_clear(signature->A_ba);
    element_clear(signature->d);
    element_clear(signature->c);
    element_clear(signature->z_x);
    element_clear(signature->z_r);
    element_clear(signature->z_alpha);
    element_clear(signature->z_beta);
    for(int i=0; i<N; i++) {
        element_clear(signature->z_i_hidden[i]);
    }
    free(signature->z_i_hidden);
    element_clear(signature->middle_res);
    
    return;
}
int main() {

    char* name = "D224";
    pairing_t* pair_use;
    pair_use = init_space(name); // it is always a pointer

    // 生成IDP私钥
    struct secret_key_IDP* sk_IDP = NULL;
    sk_IDP = init_IDP_secret_key(pair_use);

    // 生成IDP公钥，需要一个参数N
    int N = 6;
    struct public_key_IDP* pk_IDP = NULL;
    pk_IDP = init_IDP_public_key(pair_use, N, sk_IDP);

    
    // 存成链表速度比较慢，最好用数组
    // 先写一个初始版本出来，再说怎样优化
    // there should be only N-1 useful information for everyone of us

    // 获取了多个信息，information，需要进行匹配时，要如何处理呢？不明白。。
    // 可以用二进制序列来加速处理逻辑

    // struct m_i_node* user_virtual_head = get_user_info(N-1, pair_use);
    // 用户信息初始化

    // 下面是message？difficult to understand.

    // element_t的大小不是固定的，所以会出问题？
    // m需要从1开始，这是要着重注意的点，让人难以理解ing

    element_t* m_vector = (element_t*)malloc(N*sizeof(element_t));
    for(int i=0; i<N; i++) {
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
    select_vector[3] = 1;
    select_vector[1] = 1;

    // 完成complete？

    struct sigma* signature;
    signature = compute_sigma(sigma_c_user, pk_IDP, m_vector, select_vector);
    if(pk_IDP!=NULL) printf("\n successfully! \n");

    
    RP_verify(signature, m_vector, select_vector, pk_IDP);

    
    if(pk_IDP!=NULL) printf("\n successfully! \n");


    // 在free之前，要进行彻底的clear，防止堆内存溢出
    // 不能只靠signature_chedule来清理内存，对滴


    
    // 这些都是什么玄学错误？
    // clear_all(pk_IDP, sk_IDP, sigma_c_user, signature);
    
    // small_version_clear_all(pk_IDP, sk_IDP, sigma_c_user, signature);

    
    pairing_clear(*pair_use);
    free(sk_IDP);
    free(pk_IDP);
    free(sigma_c_user);
    free(signature);

    for(int i=0; i<N; i++) {
        element_clear(m_vector[i]);
    }
    free(m_vector);

    free(select_vector);
    
    

    return 0;
}