#include "read_config.h"

struct config_structure* init_test_config() {

    // 对配置文件结构体进行设置，从而提升整体程序的运行速度与效率
    struct config_structure* test_config_stru = malloc(sizeof(struct config_structure));

    test_config_stru->Elliptic_Curve_Selection = "D224";

    // 关于使用某个文件存储椭圆曲线？  让人难以接受。。。
    test_config_stru->IP_address = "192.168.50.10";

    test_config_stru->port_char = "8889";
    test_config_stru->port_num = 8889;

    test_config_stru->max_connect_thread_number_char = "5";
    test_config_stru->max_connect_thread_number_num = 5;

    test_config_stru->user_info_list = init_list();

    struct list* tmp_list = test_config_stru->user_info_list;

    // 暂时性编造一部分代码进去
    push_front("name", "wzd", NULL, tmp_list);
    push_front("location", "shanghai", NULL, tmp_list);
    push_front("age", "23", NULL, tmp_list);


    return test_config_stru;
}