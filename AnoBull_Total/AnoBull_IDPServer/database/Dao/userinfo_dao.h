#ifndef __USERINFO_DAO_H
#define __USERINFO_DAO_H

// 使用的数据库是sqlite，对的了哦
#include "all_def.h"
#include "sqlite.h"
// 下面对数据库的操作做一定的处理手段啦
// 目标是定义好接口，并且存储到数据库里面，对的啦


// 根据用户信息序列创建表格，名字叫什么呢？
// 统一命名规则：user_info_<num>  这个num就是user_info_list里面的元素数量
// 数据库主键默认为用户的名字，让名字无法重复即可
int create_user_table_by_info_infra(struct list* user_info_list);

// 获取相关的数据库api，打开数据库之后关闭数据库，这些API是很复杂的了
int insert_user_info(struct list* user_info_list);
int update_user_info(struct list* user_info_list);
int delete_user_info(struct list* user_info_list);
int get_user_info();

// how to construct the all table? damn it!
// directly 存储为一行即可
// int create_sigma_table(...);

int insert_sigma();
int delete_sigma();
// 获取用户信息即可，筛选条件应当是用户姓名
// 是否需要补一个时间戳来加速？貌似有可能是需要的了
int get_all_users_sigma();

#endif