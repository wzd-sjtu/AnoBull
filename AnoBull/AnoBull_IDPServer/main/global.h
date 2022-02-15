// 本文件用于定义全局变量

// 公开使用的全局变量，是服务器使用的内容

#ifndef __MAIN_GLOBAL_H
#define __MAIN_GLOBAL_H

// 全局读变量，完全不需要加锁
#ifdef __GLOBALS
struct secret_key_IDP* sk_IDP;
struct public_key_IDP* pk_IDP;
#else
extern struct secret_key_IDP* sk_IDP;
extern struct public_key_IDP* pk_IDP;
#endif



#endif