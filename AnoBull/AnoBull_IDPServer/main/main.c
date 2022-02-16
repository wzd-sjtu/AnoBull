// 需要一边写程序一边进行测试
#include "main.h"
#include "test.h"
#include "read_config.h"

int main() {
    // 整个程序的主架构
    // socket需要参考csapp做对应的改编
    // 从而提升程序的运行效率

    // 编码过程中的测试环节
    test_all();

    // 配置信息初始化，首先采取手动输入的方式编写
    init_test_config();
    printf("config set init successfully!\n");

    while(1);

    return 0;
}