#include "stdio.h"
#include "stdlib.h"
#include "list_own.h"


struct list* init_list() {
    // 不负责删除，删除操作是后面才需要考虑的
    struct list* my_list = malloc(sizeof(struct list));
    
    // vir_head's initialization
    my_list->vir_head = malloc(sizeof(struct list_node));
    struct list_node* tmp = my_list->vir_head;
    tmp->val1 = tmp->val2 = tmp->val3 = NULL;
    tmp->pre = NULL;
    tmp->next = NULL;

    my_list->vir_tail = malloc(sizeof(struct list_node));
    tmp = my_list->vir_tail;
    tmp->val1 = tmp->val2 = tmp->val3 = NULL;
    tmp->pre = NULL;
    tmp->next = NULL;

    // 双向链接虚拟头尾
    my_list->vir_head->next = my_list->vir_tail;
    my_list->vir_tail->pre = my_list->vir_head;

    my_list->list_num = 0;

    return my_list;
}

void push_front(void* v1, void* v2, void* v3, struct list* my_list) {
    struct list_node* tmp = malloc(sizeof(struct list_node));
    
    tmp->val1 = v1;
    tmp->val2 = v2;
    tmp->val3 = v3;

    
    tmp->pre = my_list->vir_head;
    tmp->next = my_list->vir_head->next;
    my_list->vir_head->next->pre = tmp;
    my_list->vir_head->next = tmp;
    

    // 成功完成push
    my_list->list_num++;

    return;
}

struct list_node* pop_front(struct list* my_list) {
    struct list_node* tmp = NULL;
    if(my_list->list_num <= 0) {
        return NULL;
    }
    
    tmp = my_list->vir_head->next;

    my_list->vir_head->next = tmp->next;
    tmp->next->pre = my_list->vir_head;

    // seperate the node
    tmp->next = tmp->pre = NULL;

    my_list->list_num--;

    return tmp;
}


void push_back(void* v1, void* v2, void* v3, struct list* my_list) {
    struct list_node* tmp = malloc(sizeof(struct list_node));
    tmp->val1 = v1;
    tmp->val2 = v2;
    tmp->val3 = v3;

    tmp->next = my_list->vir_tail;
    tmp->pre = my_list->vir_tail->pre;
    my_list->vir_tail->pre->next = tmp;
    my_list->vir_tail->pre = tmp;

    // 成功完成push
    my_list->list_num++;

    return;
}

struct list_node* pop_back(struct list* my_list) {
    struct list_node* tmp = NULL;
    if(my_list->list_num <= 0) {
        return NULL;
    }
    
    tmp = my_list->vir_tail->pre;

    my_list->vir_tail->pre = tmp->pre;
    tmp->pre->next = my_list->vir_tail;

    // seperate the node
    tmp->next = tmp->pre = NULL;

    my_list->list_num--;

    return tmp;
}

void traverse_show_list(struct list* my_list) {
    struct list_node* tmp = my_list->vir_head->next;
    while(tmp != my_list->vir_tail) {
        printf("data is:");
        if(tmp->val1 != NULL)
            printf("%s=", (char*)tmp->val1);
        if(tmp->val2 != NULL)
            printf("%s=", (char*)tmp->val2);
        if(tmp->val3 != NULL)
            printf("%s=", (char*)tmp->val3);
        printf("\n");

        tmp = tmp->next;
    }
    return;
}