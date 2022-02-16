#include "test.h"
#include "stdio.h"

void test_all() {
    test_list_fun();
}

void test_list_fun() {
    struct list* test_list;
    test_list = init_list();

    
    push_front(NULL, NULL, NULL, test_list);
    pop_back(test_list);
    //push_back(NULL, NULL, NULL, test_list);
    pop_front(test_list);
    

    printf("list_own test successfully!\n");
}