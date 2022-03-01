#include "userinfo_dao.h"

// dao传统上就是数据操作层，在一定程度上还是比较合理的


int create_user_table_by_info_infra(struct list* user_info_list) {
    // 根据userinfo创建对应的数据库
    
}

// 获取相关的数据库api，打开数据库之后关闭数据库，这些API是很复杂的了
// 看起来有很多无效的API，后面需要慢慢花时间解决出来了
int insert_user_info(struct list* user_info_list);
int update_user_info(struct list* user_info_list);
int delete_user_info(struct list* user_info_list);