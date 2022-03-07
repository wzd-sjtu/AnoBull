#include "stdio.h"
#include "stdlib.h"
#include "structure_to_bytes.h"
#include "all_def.h"
#include "global.h"

// just to element is ok for me

// 本文件目前只实现了公钥的内容转换，仍然有许多许多小问题

// 本质上是不需要传参数的
int pk_IDP_to_bytes_del(char* data_buffer, int data_len_limit) {
    int H_length = 0;
    int omega_length = 0, h_vector_length = 0, total_num_of_h_i_length = 0, \
        pair_length = 0, g1_length = 0, g2_length = 0;
    int each_h_vector_length = 0;

    

    omega_length = element_length_in_bytes(pk_IDP->omega);

    each_h_vector_length = element_length_in_bytes(pk_IDP->h_vector[0]);
    h_vector_length = each_h_vector_length*pk_IDP->total_num_of_h_i;

    // about how to audit? there is no necessary method to implement the project
    // should be pair transtmitted? no useful?

    // pair should be initialized in the local
    // just need a function
    // pair_length = element_length_in_bytes(*pk_IDP->pair);

    // 这个pair_choice是否要存储呢？难以理解了






    // 这行代码不明白意义
    char* pair_choice = "D224";
    pair_length = 8; // give 8 bytes to store pair_choice










    g1_length = element_length_in_bytes(pk_IDP->g1);
    g2_length = element_length_in_bytes(pk_IDP->g2);

    H_length = omega_length + h_vector_length + pair_length + \
        g1_length + g2_length;

    total_num_of_h_i_length = sizeof(pk_IDP->total_num_of_h_i);
    total_num_of_h_i_length = total_num_of_h_i_length/sizeof(unsigned char);

    H_length += (total_num_of_h_i_length + 1);  // 最后要补一个\0,标志着字符串的结束

    printf("omega_length is %d\n", H_length);
    // only nothing to store, right? 
    if(H_length > data_len_limit) {
        // 存不下数据，大小超过了上限
        printf("public key is longer than top limit.");
        return 0;
    }
    // 对于别的选择，最后会补一个斜杠0表示终止

    
    // store into it, use int function
    // firstly store the total_number 
    unsigned char* tmp_buffer = data_buffer;

    memcpy(tmp_buffer, pair_choice, strlen(pair_choice));
    // tmp_buffer[strlen(pair_choice)] = '\0';
    for(int love = strlen(pair_choice); love < pair_length; love++) {
        tmp_buffer[love] = '\0';
    }
    tmp_buffer += pair_length;

    memcpy(tmp_buffer, &pk_IDP->total_num_of_h_i, sizeof(int));
    tmp_buffer += sizeof(int);

    
    omega_length = element_to_bytes(tmp_buffer, pk_IDP->omega);
    
    element_t tmp_omega;
    element_init_G2(tmp_omega, *pk_IDP->pair);
    int another_len = element_from_bytes(tmp_omega, tmp_buffer);
    // printf("\n pre num is %d, next num is %d \n", omega_length, another_len);

    // there should be \0 stored into it?
    // 出现了一大堆玄学错误，真的是直接裂开了。。。

    if(element_cmp(tmp_omega, pk_IDP->omega)==0) {
        printf("\n failed it! \n");
    }

    tmp_buffer += omega_length;

    for(int i=0; i<pk_IDP->total_num_of_h_i; i++) {
        element_to_bytes(tmp_buffer, pk_IDP->h_vector[i]);
        tmp_buffer += each_h_vector_length;
    }
    
    
    element_to_bytes(tmp_buffer, pk_IDP->g1);
    tmp_buffer += g1_length;
    element_to_bytes(tmp_buffer, pk_IDP->g2);
    tmp_buffer += g2_length;

    // 不需要再次修改其长度
    // data_buffer[H_length-1] = '\0';

    // 存入数据区的长度

    return H_length;
}


int pk_IDP_to_bytes(char* data_buffer, int data_len_limit) {
    int H_length = 0;
    int omega_length = 0, h_vector_length = 0, total_num_of_h_i_length = 0, \
        pair_length = 0, g1_length = 0, g2_length = 0;
    int each_h_vector_length = 0;

    

    omega_length = element_length_in_bytes(pk_IDP->omega);

    each_h_vector_length = element_length_in_bytes(pk_IDP->h_vector[0]);
    h_vector_length = each_h_vector_length*pk_IDP->total_num_of_h_i;

    char* pair_choice = "D224";
    pair_length = 8; // give 8 bytes to store pair_choice

    g1_length = element_length_in_bytes(pk_IDP->g1);
    g2_length = element_length_in_bytes(pk_IDP->g2);

    H_length = omega_length + h_vector_length + pair_length + \
        g1_length + g2_length;

    total_num_of_h_i_length = sizeof(pk_IDP->total_num_of_h_i);
    total_num_of_h_i_length = total_num_of_h_i_length/sizeof(unsigned char);

    H_length += (total_num_of_h_i_length + 1);  // 最后要补一个\0,标志着字符串的结束

    printf("pk_idp bytes' length is %d\n", H_length);

    unsigned char* tmp_buffer = data_buffer;

    memcpy(tmp_buffer, pair_choice, strlen(pair_choice));
    // tmp_buffer[strlen(pair_choice)] = '\0';
    for(int love = strlen(pair_choice); love < pair_length; love++) {
        tmp_buffer[love] = '\0';
    }
    tmp_buffer += pair_length;

    memcpy(tmp_buffer, &pk_IDP->total_num_of_h_i, sizeof(int));
    tmp_buffer += sizeof(int);

    
    omega_length = element_to_bytes(tmp_buffer, pk_IDP->omega);

    tmp_buffer += omega_length;

    // 排查bug 排查地心态有点小崩
    for(int i=0; i<pk_IDP->total_num_of_h_i; i++) {
        element_to_bytes(tmp_buffer, pk_IDP->h_vector[i]);
        tmp_buffer += each_h_vector_length;
    }
    
    
    element_to_bytes(tmp_buffer, pk_IDP->g1);
    tmp_buffer += g1_length;
    element_to_bytes(tmp_buffer, pk_IDP->g2);
    tmp_buffer += g2_length;

    data_buffer[H_length-1] = '\0';

    return H_length;
}

// length是可以在网络通信中完成传递的
// 这个from函数是需要处理的了
struct public_key_IDP* pk_IDP_from_bytes(unsigned char* data_buffer, int length) {
    // needed to use the API
    // int element_from_bytes(element_t e, unsigned char *data)
    int H_length = 0;
    int omega_length = 0, h_vector_length = 0, \
        g1_length = 0, g2_length = 0;

    int total_num_of_h_i_length = sizeof(int);

    int each_h_vector_length = 0;
    int pair_length = 8;

    char pair_choice[8] = {0};

    // 这里进行了公钥的生成
    // 考虑到公钥只生成一次，所以写在哪里是无所谓的了
    struct public_key_IDP* res_pk_IDP = (struct public_key_IDP*)malloc(sizeof(struct public_key_IDP));
    
    unsigned char* tmp_buffer = data_buffer;

    
    // using the pair choice to initialize the pair
    memcpy(pair_choice, tmp_buffer, pair_length);
    tmp_buffer += pair_length;

    // printf("chosen group is ");
    // printf(pair_choice);
    // printf("\n");

    // init the pair space, what happened?? should be initialized the pair firstly?
    res_pk_IDP->pair = init_space(pair_choice);
    // then set the group of element

    
    element_init_G2(res_pk_IDP->omega, *res_pk_IDP->pair);
    element_init_G1(res_pk_IDP->g1, *res_pk_IDP->pair);
    element_init_G2(res_pk_IDP->g2, *res_pk_IDP->pair);

    
    
    // always from order to implement the data_buffer
    memcpy(&res_pk_IDP->total_num_of_h_i, tmp_buffer, sizeof(int));
    tmp_buffer += total_num_of_h_i_length;  // store into the length of idp
    int N = res_pk_IDP->total_num_of_h_i;

    printf("chose h_vector dimentions are %d \n", N);

    omega_length = element_from_bytes(res_pk_IDP->omega, tmp_buffer);
    tmp_buffer += omega_length;

    
    // firstly to read the each h_length
    // initialize of h_i, for use of h_vector
    res_pk_IDP->h_vector = (element_t *)malloc(N*sizeof(element_t));
    // each_h_vector_length = element_from_bytes(res_pk_IDP->h_vector[0], tmp_buffer);
    // tmp_buffer += each_h_vector_length;
    for(int i=0; i<N; i++) {
        // firstly initialize the space
        element_init_G1(res_pk_IDP->h_vector[i], *res_pk_IDP->pair);
        each_h_vector_length = element_from_bytes(res_pk_IDP->h_vector[i], tmp_buffer);
        tmp_buffer += each_h_vector_length;
    }

    
    g1_length = element_from_bytes(res_pk_IDP->g1, tmp_buffer);
    tmp_buffer += g1_length;

    g2_length = element_from_bytes(res_pk_IDP->g2, tmp_buffer);
    tmp_buffer += g2_length;
    
    return res_pk_IDP;
}

int comapre_pk_IDP(struct public_key_IDP* new_pk_IDP) {
    int res = 0;
    if(element_cmp(pk_IDP->omega, new_pk_IDP->omega) != 0) {
        // printf("yes!");
        return 0;
    }
    if(pk_IDP->total_num_of_h_i != new_pk_IDP->total_num_of_h_i) {
        return 0;
    }
    for(int i=0; i<pk_IDP->total_num_of_h_i; i++) {
        if(element_cmp(pk_IDP->h_vector[i], new_pk_IDP->h_vector[i]) != 0) {
            return 0;
        }
    }
    if(element_cmp(pk_IDP->g1, new_pk_IDP->g1) != 0) {
        return 0;
    }
    if(element_cmp(pk_IDP->g2, new_pk_IDP->g2) != 0) {
        return 0;
    }
    return 1;
}


// a lot of unsolved problem just take place!

int sigma_c_to_bytes(struct sigma_c* will_send_sigma_c, char* data_buffer, int data_len_limit) {
    // another convert function
    // which is always complex for me to build it.
    int tmp_store_len = 0;
    int total_len = 0;

    char* tmp_buffer = data_buffer;
    tmp_store_len = element_to_bytes(data_buffer, will_send_sigma_c->x);
    total_len += tmp_store_len;
    
    data_buffer += tmp_store_len;
    tmp_store_len = element_to_bytes(data_buffer, will_send_sigma_c->s);
    total_len += tmp_store_len;

    data_buffer += tmp_store_len;
    tmp_store_len = element_to_bytes(data_buffer, will_send_sigma_c->A);
    total_len += tmp_store_len;

    data_buffer += tmp_store_len;
    tmp_store_len = element_to_bytes(data_buffer, will_send_sigma_c->middle_res);
    total_len += tmp_store_len;

    return total_len;
}



// 这里还需要别的api来做相关的处理的哦。
struct sigma_c* sigma_c_from_bytes(char* data_buffer, int length, struct public_key_IDP* pk_IDP) {
    // 下面对thing做一个恢复
    // 这个api对于user端来说，也是成立的
    struct sigma_c* res_sigma_c = (struct sigma_c*)malloc(sizeof(struct sigma_c));

    element_init_Zr(res_sigma_c->x, *pk_IDP->pair);
    element_init_Zr(res_sigma_c->s, *pk_IDP->pair);

    element_init_G1(res_sigma_c->A, *pk_IDP->pair);

    element_init_G1(res_sigma_c->middle_res, *pk_IDP->pair);

    char* tmp_buffer = data_buffer;

    int tmp_len = 0;

    tmp_len = element_from_bytes(res_sigma_c->x, tmp_buffer);
    tmp_buffer += tmp_len;

    tmp_len = element_from_bytes(res_sigma_c->s, tmp_buffer);
    tmp_buffer += tmp_len;

    tmp_len = element_from_bytes(res_sigma_c->A, tmp_buffer);
    tmp_buffer += tmp_len;

    tmp_len = element_from_bytes(res_sigma_c->middle_res, tmp_buffer);
    tmp_buffer += tmp_len;

    // successfully get the target result.
    return res_sigma_c;
}

// to and from are both needed.
int sigma_to_bytes(struct sigma* will_send_sigma, char* data_buffer, int data_len_limit, struct public_key_IDP* pk_IDP) {
    // another convert function
    // which is always complex for me to build it.
    int tmp_store_len = 0;
    int total_len = 0;

    char* tmp_buffer = data_buffer;
    tmp_store_len = element_to_bytes(data_buffer, will_send_sigma->A_plus);
    total_len += tmp_store_len;
    
    data_buffer += tmp_store_len;
    tmp_store_len = element_to_bytes(data_buffer, will_send_sigma->A_ba);
    total_len += tmp_store_len;

    data_buffer += tmp_store_len;
    tmp_store_len = element_to_bytes(data_buffer, will_send_sigma->d);
    total_len += tmp_store_len;

    data_buffer += tmp_store_len;
    tmp_store_len = element_to_bytes(data_buffer, will_send_sigma->c);
    total_len += tmp_store_len;

    data_buffer += tmp_store_len;
    tmp_store_len = element_to_bytes(data_buffer, will_send_sigma->z_x);
    total_len += tmp_store_len;

    data_buffer += tmp_store_len;
    tmp_store_len = element_to_bytes(data_buffer, will_send_sigma->z_r);
    total_len += tmp_store_len;

    data_buffer += tmp_store_len;
    tmp_store_len = element_to_bytes(data_buffer, will_send_sigma->z_alpha);
    total_len += tmp_store_len;

    data_buffer += tmp_store_len;
    tmp_store_len = element_to_bytes(data_buffer, will_send_sigma->z_beta);
    total_len += tmp_store_len;

    int N = pk_IDP->total_num_of_h_i;
    for(int i=0; i<N; i++) {
        data_buffer += tmp_store_len;
        tmp_store_len = element_to_bytes(data_buffer, will_send_sigma->z_i_hidden[i]);
        total_len += tmp_store_len;
    }

    // 最终完成整个数据结构的存储
    return total_len;
}


struct sigma* sigma_from_bytes(char* data_buffer, int length, struct public_key_IDP* pk_IDP, char** m_vector_point) {
    // another convert function
    // which is always complex for me to build it.

    // 进行了无脑的数组串的转化与生成
    // 现在就是玄学，真实吐了
    struct sigma* res_sigma = (struct sigma*)malloc(sizeof(struct sigma));

    
    
    element_init_G1(res_sigma->A_plus, *pk_IDP->pair);
    element_init_G1(res_sigma->A_ba, *pk_IDP->pair);
    element_init_G1(res_sigma->d, *pk_IDP->pair);
    element_init_Zr(res_sigma->c, *pk_IDP->pair);

    element_init_Zr(res_sigma->z_x, *pk_IDP->pair);
    element_init_Zr(res_sigma->z_r, *pk_IDP->pair);
    element_init_Zr(res_sigma->z_alpha, *pk_IDP->pair);
    element_init_Zr(res_sigma->z_beta, *pk_IDP->pair);

    int N = pk_IDP->total_num_of_h_i;

    // 这里的确进行了远程赋值
    res_sigma->z_i_hidden = (element_t*)malloc(N*sizeof(element_t));
    for(int i=0; i<N; i++) {
        element_init_Zr(res_sigma->z_i_hidden[i], *pk_IDP->pair);
    }

    char* tmp_buffer = data_buffer;
    int tmp_len = 0;

    
    tmp_len = element_from_bytes(res_sigma->A_plus, tmp_buffer);
    tmp_buffer += tmp_len;

    tmp_len = element_from_bytes(res_sigma->A_ba, tmp_buffer);
    tmp_buffer += tmp_len;

    tmp_len = element_from_bytes(res_sigma->d, tmp_buffer);
    tmp_buffer += tmp_len;

    tmp_len = element_from_bytes(res_sigma->c, tmp_buffer);
    tmp_buffer += tmp_len;

    tmp_len = element_from_bytes(res_sigma->z_x, tmp_buffer);
    tmp_buffer += tmp_len;

    tmp_len = element_from_bytes(res_sigma->z_r, tmp_buffer);
    tmp_buffer += tmp_len;

    tmp_len = element_from_bytes(res_sigma->z_alpha, tmp_buffer);
    tmp_buffer += tmp_len;

    tmp_len = element_from_bytes(res_sigma->z_beta, tmp_buffer);
    tmp_buffer += tmp_len;

    
    for(int i=0; i<N; i++) {
        tmp_len = element_from_bytes(res_sigma->z_i_hidden[i], tmp_buffer);
        tmp_buffer += tmp_len;
    }
    
    // 希望二级指针原地改变
    // 成功get到了sigma，为后文的处理打下基础
    *m_vector_point = tmp_buffer;

    return res_sigma;
}

int compare_sigma(struct sigma* var1, struct sigma* var2) {
    if(element_cmp(var1->A_plus, var2->A_plus) != 0) {
        printf("[ERROR] A_plus wrong!\n");
        return -1;
    }
    else if(element_cmp(var1->A_ba, var2->A_ba) != 0) {
        printf("[ERROR] A_ba wrong!\n");
    }
    else if(element_cmp(var1->d, var2->d) != 0) {
        printf("[ERROR] d wrong!\n");
    }
    else if(element_cmp(var1->c, var2->c) != 0) {
        printf("[ERROR] c wrong!\n");
    }
    else if(element_cmp(var1->z_x, var2->z_x) != 0) {
        printf("[ERROR] z_x wrong!\n");
    }
    else if(element_cmp(var1->z_r, var2->z_r) != 0) {
        printf("[ERROR] z_r wrong!\n");
    }
    else if(element_cmp(var1->z_alpha, var2->z_alpha) != 0) {
        printf("[ERROR] z_alpha wrong!\n");
    }
    else if(element_cmp(var1->z_beta, var2->z_beta) != 0) {
        printf("[ERROR] z_beta wrong!\n");
    }

    return 1;
}


// for sigma_store function
// how to use it in high speed?

// to and from are both needed.
int sigma_store_to_bytes(struct sigma_store* will_send_sigma, char* data_buffer, int data_len_limit, struct public_key_IDP* pk_IDP) {
    // another convert function
    // which is always complex for me to build it.
    int tmp_store_len = 0;
    int total_len = 0;

    char* tmp_buffer = data_buffer;
    tmp_store_len = element_to_bytes(data_buffer, will_send_sigma->A_plus);
    total_len += tmp_store_len;
    
    data_buffer += tmp_store_len;
    tmp_store_len = element_to_bytes(data_buffer, will_send_sigma->A_ba);
    total_len += tmp_store_len;

    data_buffer += tmp_store_len;
    tmp_store_len = element_to_bytes(data_buffer, will_send_sigma->d);
    total_len += tmp_store_len;


    data_buffer += tmp_store_len;
    tmp_store_len = element_to_bytes(data_buffer, will_send_sigma->R2);
    total_len += tmp_store_len;


    data_buffer += tmp_store_len;
    tmp_store_len = element_to_bytes(data_buffer, will_send_sigma->c);
    total_len += tmp_store_len;

    data_buffer += tmp_store_len;
    tmp_store_len = element_to_bytes(data_buffer, will_send_sigma->z_x);
    total_len += tmp_store_len;

    data_buffer += tmp_store_len;
    tmp_store_len = element_to_bytes(data_buffer, will_send_sigma->z_r);
    total_len += tmp_store_len;

    data_buffer += tmp_store_len;
    tmp_store_len = element_to_bytes(data_buffer, will_send_sigma->z_alpha);
    total_len += tmp_store_len;

    data_buffer += tmp_store_len;
    tmp_store_len = element_to_bytes(data_buffer, will_send_sigma->z_beta);
    total_len += tmp_store_len;

    int N = pk_IDP->total_num_of_h_i;
    for(int i=0; i<N; i++) {
        data_buffer += tmp_store_len;
        tmp_store_len = element_to_bytes(data_buffer, will_send_sigma->z_i_hidden[i]);
        total_len += tmp_store_len;
    }

    // 最终完成整个数据结构的存储
    return total_len;
}


struct sigma_store* sigma_store_from_bytes(char* data_buffer, int length, struct public_key_IDP* pk_IDP, char** m_vector_point) {
    // another convert function
    // which is always complex for me to build it.

    // 进行了无脑的数组串的转化与生成
    // 现在就是玄学，真实吐了
    struct sigma_store* res_sigma = (struct sigma_store*)malloc(sizeof(struct sigma_store));

    
    
    element_init_G1(res_sigma->A_plus, *pk_IDP->pair);
    element_init_G1(res_sigma->A_ba, *pk_IDP->pair);
    element_init_G1(res_sigma->d, *pk_IDP->pair);
    element_init_G1(res_sigma->R2, *pk_IDP->pair);

    element_init_Zr(res_sigma->c, *pk_IDP->pair);

    element_init_Zr(res_sigma->z_x, *pk_IDP->pair);
    element_init_Zr(res_sigma->z_r, *pk_IDP->pair);
    element_init_Zr(res_sigma->z_alpha, *pk_IDP->pair);
    element_init_Zr(res_sigma->z_beta, *pk_IDP->pair);

    int N = pk_IDP->total_num_of_h_i;

    // 这里的确进行了远程赋值
    res_sigma->z_i_hidden = (element_t*)malloc(N*sizeof(element_t));
    for(int i=0; i<N; i++) {
        element_init_Zr(res_sigma->z_i_hidden[i], *pk_IDP->pair);
    }

    char* tmp_buffer = data_buffer;
    int tmp_len = 0;

    
    tmp_len = element_from_bytes(res_sigma->A_plus, tmp_buffer);
    tmp_buffer += tmp_len;

    tmp_len = element_from_bytes(res_sigma->A_ba, tmp_buffer);
    tmp_buffer += tmp_len;

    tmp_len = element_from_bytes(res_sigma->d, tmp_buffer);
    tmp_buffer += tmp_len;

    tmp_len = element_from_bytes(res_sigma->R2, tmp_buffer);
    tmp_buffer += tmp_len;

    tmp_len = element_from_bytes(res_sigma->c, tmp_buffer);
    tmp_buffer += tmp_len;

    tmp_len = element_from_bytes(res_sigma->z_x, tmp_buffer);
    tmp_buffer += tmp_len;

    tmp_len = element_from_bytes(res_sigma->z_r, tmp_buffer);
    tmp_buffer += tmp_len;

    tmp_len = element_from_bytes(res_sigma->z_alpha, tmp_buffer);
    tmp_buffer += tmp_len;

    tmp_len = element_from_bytes(res_sigma->z_beta, tmp_buffer);
    tmp_buffer += tmp_len;

    
    for(int i=0; i<N; i++) {
        tmp_len = element_from_bytes(res_sigma->z_i_hidden[i], tmp_buffer);
        tmp_buffer += tmp_len;
    }
    
    // 希望二级指针原地改变
    // 成功get到了sigma，为后文的处理打下基础
    *m_vector_point = tmp_buffer;

    return res_sigma;
}