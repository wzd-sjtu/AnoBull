#include "sqlite3_use.h"
// 再次补充了一个数据库文件，为以后的编写打下对应的基础了

// 工具函数
// 无脑将两个sql合并在一起

char* connect_sql_string(char* pre, char* end) {
	while(*end != '\0') {
		// printf("node is %s\n", end);
		*pre = *end;
		pre++;
		end++;
	}
	*pre = '\0';
	// end一般是固定的指针，不需要change，否则会报段错误
	// *end = '\0';

	// 对sql进行加减后，下一个位置
	// printf("go to the end location!\n");
	return pre;
}

int sqlite_init(const char *db_path)
{
	// ret是返回的数据库打开指针？
	int ret;

	// 启用串行或并行模式
    ret = sqlite3_config(SQLITE_MOD);//设置为规定模式

    if (ret != SQLITE_OK) {
        printf("[ERROR] SQLite3 is not compiled with serialized or multithread threading mode!\n");
        return -1;
    }

	//sqlite初始化
	ret = sqlite3_initialize();
	if (ret != SQLITE_OK) {
		perror("[ERROR] database_init sqlite_initalize error\n");
		return -1;;
	}

	// db 看起来没有必要上全局变量，难以理解

	// 轮流open文件即可
	/*
	ret = sqlite3_open(db_path, &db);
	if (ret) {
		// open the database as we see.
		printf("[ERROR] Can't open sql: %s\n", sqlite3_errmsg(db));
		return -1;
	}
	*/

	return ret;
}


// 根据info_list完成基本内容的配置
// 在一定程度上这是非常合理的了哦
int create_table_by_list(struct list* user_info_list) {
    // 根据user_info_list设置表
    sqlite3 *db;
	char* zErrMsg = NULL;
	int ret = 0;

	ret = sqlite3_open(DB_PATH, &db);
	if(ret != SQLITE_OK) {
		printf("[ERROR] Can't open database: %s\n", sqlite3_errmsg(db));
		return 0;
	}
	else {
		printf("[INFO] Open database successfully\n");
	}

	// 需要执行的sql语句，这股语句存在溢出的可能性possibility
	char sql_buffer[SQL_MAX_LINE] = {0};
	char buffer[SQL_MAX_LINE] = {0};
	char* tmp = sql_buffer;
	// 将buffer内容向目标tmp写入，从而完成基本的内容书写

	
	tmp = connect_sql_string(tmp, "create table if not exists user_info_");

	// printf("number is %d\n", user_info_list->list_num);
	buffer[0] = (char)(user_info_list->list_num + '0');
	buffer[1] = '\0';
	// printf("char string is buffer %s\n", buffer);
	tmp = connect_sql_string(tmp, buffer);

	tmp = connect_sql_string(tmp, " (");

	// 循环填入重要info的列的名字
	struct list_node* tmp_list_node = user_info_list->vir_head->next;
	
	char* buffer_tmp = tmp;

	
	for(int i=0; i<user_info_list->list_num; i++) {
		buffer_tmp = connect_sql_string(buffer_tmp, tmp_list_node->val1);
		if(strcmp(tmp_list_node->val1, "name") == 0) {
			buffer_tmp = connect_sql_string(buffer_tmp, " text primary key not null");
		}
		else {
			buffer_tmp = connect_sql_string(buffer_tmp, " text not null");
		}
		
		if(i == user_info_list->list_num-1) {
			buffer_tmp = connect_sql_string(buffer_tmp, ")");
		}
		else {
			buffer_tmp = connect_sql_string(buffer_tmp, ",");
		}
		tmp_list_node = tmp_list_node->next;
	}
	// 至此完成sql的构建，直接运行

	ret = sqlite3_exec(db, sql_buffer, NULL, NULL, &zErrMsg);
	// printf("sql is %s\n", sql_buffer);

	if(ret != SQLITE_OK) {
		printf("[ERROR] SQL error:%s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}
	else {
		printf("[INFO] create table successfully!\n");
	}
	

	sqlite3_close(db);

	return ret;

}

int insert_user_info_by_list(struct list* user_info_list) {
	// 存入用户基本信息
	// 如果主键重复，会提示名字已经被占用
	// 或者使用有关的update
	// userinfo会给出表的名字 对应的information
    // 根据user_info_list设置表
    sqlite3 *db;
	char* zErrMsg = NULL;
	int ret = 0;

	ret = sqlite3_open(DB_PATH, &db);
	// 这里的info貌似不需要完全打印，存储在文件缓冲区是比较好的选择
	if(ret != SQLITE_OK) {
		printf("[ERROR] Can't open database: %s\n", sqlite3_errmsg(db));
		return 0;
	}
	else {
		printf("[INFO] Open database successfully\n");
	}

	// 需要执行的sql语句，这股语句存在溢出的可能性possibility
	char sql_buffer[SQL_MAX_LINE] = {0};
	char buffer[SQL_MAX_LINE] = {0};
	char* tmp = sql_buffer;
	// 将buffer内容向目标tmp写入，从而完成基本的内容书写

	// 插入到对应的表格里面
	tmp = connect_sql_string(tmp, "replace into user_info_");

	// printf("number is %d\n", user_info_list->list_num);
	buffer[0] = (char)(user_info_list->list_num + '0');
	buffer[1] = ' ';
	buffer[2] = '\0';

	// printf("char string is buffer %s\n", buffer);
	tmp = connect_sql_string(tmp, buffer);

	tmp = connect_sql_string(tmp, " (");

	// 循环填入重要info的列的名字
	struct list_node* tmp_list_node = user_info_list->vir_head->next;
	
	char* buffer_tmp = tmp;

	for(int i=0; i<user_info_list->list_num; i++) {
		buffer_tmp = connect_sql_string(buffer_tmp, tmp_list_node->val1);
		
		if(i == user_info_list->list_num-1) {
			buffer_tmp = connect_sql_string(buffer_tmp, ")");
		}
		else {
			buffer_tmp = connect_sql_string(buffer_tmp, ",");
		}
		tmp_list_node = tmp_list_node->next;
	}
	// 至此完成表格内部信息存储
	// 下面再做别的处理
	buffer_tmp = connect_sql_string(buffer_tmp, " values (");

	tmp_list_node = user_info_list->vir_head->next;
	for(int i=0; i<user_info_list->list_num; i++) {
		buffer_tmp = connect_sql_string(buffer_tmp, "\'");
		buffer_tmp = connect_sql_string(buffer_tmp, tmp_list_node->val2);
		
		if(i == user_info_list->list_num-1) {
			buffer_tmp = connect_sql_string(buffer_tmp, "\');");
		}
		else {
			buffer_tmp = connect_sql_string(buffer_tmp, "\',");
		}
		tmp_list_node = tmp_list_node->next;
	}

	// 至此 成功完成basic信息的插入insert
	
	ret = sqlite3_exec(db, sql_buffer, NULL, NULL, &zErrMsg);
	// printf("sql is %s\n", sql_buffer);

	if(ret != SQLITE_OK) {
		printf("[ERROR] SQL error:%s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}
	else {
		printf("[INFO] insert or update user info successfully!\n");
		printf("[INFO] replace sentence is \n[SQL SENTENCE] %s\n", sql_buffer);
	}
	
	// 处理完记得close数据库
	sqlite3_close(db);
	return ret;
}


int create_table_sigma_c() {
	// 直接create对应的information即可得之
}