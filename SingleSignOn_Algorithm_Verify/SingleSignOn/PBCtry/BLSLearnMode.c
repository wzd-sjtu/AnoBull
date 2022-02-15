#include "/usr/local/include/pbc/pbc.h"
#include "/usr/local/include/pbc/pbc_test.h"
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <stdlib.h>

// the code to compile the target document
// gcc BLS.c -L. -lpbc -lgmp -lcrypto

char param[1347] = "type d \
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

int main() {

    pairing_t pairing;
    //char param[1024] = {'0'};
    size_t count = strlen(param);
    // printf("%d\n", count);
    // 经测试，d224椭圆曲线参数数组大小为1346，故将大小初始化为1347byte，即为char param[1347]
    pairing_init_set_buf(pairing, param, count);

    // 系统参数g
    element_t g, h;
    // Alice公钥和私钥
    element_t public_key, secret_key;
    // 签名
    element_t sig; // \sigma的缩写
    // 中间变量
    element_t temp1, temp2;
    
    // init作用就是标明这些参数属于哪个域或者群

    // 用群G2对g和公钥初始化
    element_init_G2(g, pairing);
    element_init_G2(public_key, pairing);
    // 用群G1对h和sig初始化
    element_init_G1(h, pairing);
    element_init_G1(sig, pairing);
    // 用群GT对两个中间变量初始化
    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);

    // 用整数群对私钥初始化
    element_init_Zr(secret_key, pairing);


    // 生成系统参数
    element_random(g);

    // 生成用户私钥
    element_random(secret_key);

    // 生成公钥
    element_pow_zn(public_key, g, secret_key);

    char* message = "ABCDEF";

    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, message, strlen(message));

    unsigned char result[32];

    SHA256_Final(result, &sha256_ctx);
    // 计算哈希，这里用map来代替了哈希运算，得到h
    printf(result); // complex status of sha256
    printf("\n");

    // map the hash str result to the element in G_1
    element_from_hash(h, result, strlen(result));

    // 签名
    element_pow_zn(sig, h, secret_key);

    // Bob收到签名和消息后，对信息进行验证

    // 双线性对映射
    pairing_apply(temp1, sig, g, pairing);
    pairing_apply(temp2, h, public_key, pairing);

    // 比较两个签名是否相同
    if (!element_cmp(temp1, temp2)) {
        printf("signature verifies\n");
    } else {
        printf("signature does not verify\n");
    }
    
    // printf("successfully initial!\n");

    return 0;
}