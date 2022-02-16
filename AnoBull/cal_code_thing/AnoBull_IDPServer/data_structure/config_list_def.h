#ifndef __CONFIG_LIST_DEF
#define __CONFIG_LIST_DEF

#include "/usr/local/include/pbc/pbc.h"
#include "/usr/local/include/pbc/pbc_test.h"
#include "stdio.h"
#include "stdlib.h"
#include <string.h>
#include <openssl/sha.h>

#include "stdint_p.h"



// 需要将config使用一个结构体来描绘
struct config_structure {
    // 内部需要补充相关的重要信息
    // 这里要存储整个配置文件的所有信息
    // 当读入文件时，这个充当一个中间层来做不同的处理
    // 此处需要定义配置文件的所有信息，为将来的处理打下基础

    // 选择的密码群
    char* Elliptic_Curve_Selection;

    // IP地址
    char* IP_address;

    // 端口，考虑转变为数字？
    char* port_char;
    uint32_t_p port_num;

    // 允许连接的最大数目
    char* max_connect_thread_number_char;
    uint32_t_p max_connect_thread_number_num;

    // 用户需要填写的信息链表，暂时给出需要填写的信息格式
    // 填充所有的val1的信息，信息的格式应当是什么？此信息需要提前存储，不考虑鲁棒性
    // val1是信息名字，val2是信息格式
    struct list* user_info_list;

    // 配置文件还可以加入什么别的信息呢？
};


#endif