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

struct config_structure* read_config_init() {

    char buffer[MAX_LINE_READ_CONFIG] = {0};

    FILE* config_file;

    struct config_structure* test_config_stru = malloc(sizeof(struct config_structure));
    
    test_config_stru->user_info_list = init_list();
    struct list* tmp_list = test_config_stru->user_info_list;
    
    config_file = fopen(CONFIG_DOCUMENT_PATH, "r");

    int read_res = 0;

    // 这里的fscanf出现了一点点的问题 problem

    char buffer_name[MAX_LINE_READ_CONFIG] = {0};
    char buffer_value[MAX_LINE_READ_CONFIG] = {0};

    
    // 下面需要存入一个状态机
    // 0表示起始状态
    // 1表示椭圆曲线
    // 2表示IP地址
    // 3表示端口
    // 4表示允许连接最大数目
    // 5表示进入User_structure状态
    // 6表示active
    // 7表示passive

    // 8表示用户name
    // 9表示用户value
    // 最后返回到起始状态


    // 最好是把这些信息存入数据库，这样速度才能达到最快
    int state = 0;

    int buffer_len_name = 0;
    int buffer_len_value = 0;

    while(!feof(config_file)) {
        // read_res = fscanf(config_file, "%[^\n]", buffer);
        char* tmp = fgets(buffer, MAX_LINE_READ_CONFIG-1, config_file);
        if(tmp == NULL) break;
        
        int read_res = strlen(buffer);
        buffer[read_res] = '\0';
        //printf(buffer);
        // printf("\n");

        // successfully完成了配置文件读取
        if(read_res == 0) continue;
        if(buffer[0] == ' ' || buffer[0] == '#' || buffer[0] == '\n') continue;

        int i = 0, j = 0;

        while( i<read_res && buffer[i] != ' ' && buffer[i] != '=' && buffer[i] != '\n') {
            buffer_name[i] = buffer[i];
            i++;
        }
        buffer_name[i] = '\0'; // end of string
        while(i<read_res && (buffer[i] == ' ' || buffer[i] == '=')) {
            i++;
        }
        while(i<read_res && buffer[i] != '\n') {
            buffer_value[j] = buffer[i];
            i++;
            j++; 
        }
        buffer_value[j] = '\0';
        
        //printf("line length is %d", read_res);
        //printf("each line ");
        // printf(buffer);
        // 最后补充一个'\0'
        // printf(buffer_name);printf("\n");
        // printf(buffer_value);printf("\n");

        if(state == 0) {
            if(strcmp(buffer_name, "Elliptic_Curve_Selection") == 0) {
                state = 1;
            }
            else if(strcmp(buffer_name, "IP_address") == 0) {
                state = 2;
            }
            else if(strcmp(buffer_name, "port") == 0) {
                state = 3;
            }
            else if(strcmp(buffer_name, "max_connect_thread_num") == 0) {
                state = 4;
            }
            else if(strcmp(buffer_name, "user_info_structure") == 0) {
                state = 5;
            }
        }

        buffer_len_value = strlen(buffer_value);

        if(state == 1) {
            test_config_stru->Elliptic_Curve_Selection = \
                malloc(buffer_len_value + 1);
            strcpy(test_config_stru->Elliptic_Curve_Selection, buffer_value);
            // '\0'会自动进行++处理
            // test_config_stru->Elliptic_Curve_Selection[buffer_len_value] = '\0';
            state = 0;
        }
        else if(state == 2) {
            test_config_stru->IP_address = \
                malloc(buffer_len_value + 1);
            strcpy(test_config_stru->IP_address, buffer_value);
            state = 0;
        }
        else if(state == 3) {
            test_config_stru->port_char = \
                malloc(buffer_len_value + 1);
            strcpy(test_config_stru->port_char, buffer_value);
            state = 0;
        }
        else if(state == 4) {
            test_config_stru->max_connect_thread_number_char = \
                malloc(buffer_len_value + 1);
            strcpy(test_config_stru->max_connect_thread_number_char, buffer_value);
            state = 0;
        }
        else if(state == 5) {
            if(strcmp(buffer_value, "Active") == 0) {
                state = 6;
            }
            else state = 7;
        }


        if(state == 6) {
            // 状态六，进行无尽循环，后文都是配置信息
            char* tmp1 = malloc(strlen(buffer_name) + 1);
            char* tmp2 = malloc(strlen(buffer_value) + 1);

            strcpy(tmp1, buffer_name);
            strcpy(tmp2, buffer_value);

            printf(tmp1);printf(" = ");printf(tmp2);printf("\n");

            // 进行数据存储
            push_front(tmp1, tmp2, NULL, test_config_stru->user_info_list);
        }
        else if(state == 7) {

        }
    }
    // 多读了一个配置参数
    pop_front(test_config_stru->user_info_list);

    // 下面再进行数字转换
    // int number_of_char = 0;
    printf("after the push, the user info number is %d\n", test_config_stru->user_info_list->list_num);

    test_config_stru->port_num = atoi(test_config_stru->port_char);
    test_config_stru->max_connect_thread_number_num = atoi(test_config_stru->max_connect_thread_number_char);


    // 处理完记得关闭文件流

    
    fclose(config_file);

    return test_config_stru;

}