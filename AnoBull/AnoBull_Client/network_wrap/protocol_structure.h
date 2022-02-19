#ifndef __PROTOCOL_STRUCTURE_H
#define __PROTOCOL_STRUCTURE_H

// try to define the length..
#include "stdint_p.h"
// 这里对通信协议的结构做一个定义

// 报文头长度为8byts,也就是8个字节
struct protocol_header {
    // 标志位，用于存储多余信息
    uint8_t_p sig_pro;
    // 存储协议状态信息
    uint8_t_p state;
    // 专门用于对齐
    uint16_t_p unused_bits_1;
    // 报文长度,单位为byts，以字节为单位
    uint16_t_p length;
    // 未使用的内容
    uint16_t_p unused_bits_2;
};

#endif