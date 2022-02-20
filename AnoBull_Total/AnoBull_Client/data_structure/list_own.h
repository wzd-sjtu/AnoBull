#ifndef __LIST_OWN_H
#define __LIST_OWN_H

#include "stdio.h"
#include "stdlib.h"

// 可以制造一个统一的链表，从而提升运行的速率，这是非常重要的了
struct list {
    // 只读列表，不需要存储别的内容
    // 存储成为一个双向链表，同时具有头尾内容

    struct list_node* vir_head;
    struct list_node* vir_tail;
    int list_num;
};

struct list_node {

    // 在这里构建双向链表，为后文的处理打下基础

    // 链表里面的指针是否需要free掉？暂时不处理它们
    void* val1;
    void* val2;
    void* val3;

    struct list_node* pre;
    struct list_node* next;
};

// how to traverse?  it is temporaryly uncertain
// you could just easily use your name!

struct list* init_list();
void push_front(void* v1, void* v2, void* v3, struct list* my_list);
struct list_node* pop_front(struct list* my_list);
void push_back(void* v1, void* v2, void* v3, struct list* my_list);
struct list_node* pop_back(struct list* my_list);
void traverse_show_list(struct list* my_list);

#endif