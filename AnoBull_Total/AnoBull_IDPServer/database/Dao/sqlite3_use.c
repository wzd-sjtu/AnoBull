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

// 为何要把用户信息存入数据库？这是难以完全理解的了
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
	}
	else {
		printf("[INFO] create table successfully!\n");
	}
	

	sqlite3_free(zErrMsg);
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
	}
	else {
		printf("[INFO] insert or update user info successfully!\n");
		printf("[INFO] replace sentence is \n[SQL SENTENCE] %s\n", sql_buffer);
	}
	
	// 处理完记得close数据库
	sqlite3_free(zErrMsg);
	sqlite3_close(db);
	return ret;
}

// 表格的名字需要修改
int create_table_sigma_c(struct list* user_info_list) {
	// 直接create对应的information即可得之
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
	char buffer[10] = {0};
	char* tmp = sql_buffer;
	// 将buffer内容向目标tmp写入，从而完成基本的内容书写

	
	tmp = connect_sql_string(tmp, "create table if not exists user_sigma_c_");

	// printf("number is %d\n", user_info_list->list_num);
	buffer[0] = (char)(user_info_list->list_num + '0');
	buffer[1] = '\0';
	// printf("char string is buffer %s\n", buffer);
	tmp = connect_sql_string(tmp, buffer);

	tmp = connect_sql_string(tmp, " (name text primary key not null, sigma_c text not null);");

	ret = sqlite3_exec(db, sql_buffer, NULL, NULL, &zErrMsg);
	// printf("sql is %s\n", sql_buffer);

	if(ret != SQLITE_OK) {
		printf("[ERROR] SQL error:%s\n", zErrMsg);
	}
	else {
		printf("[INFO] create table successfully!\n");
	}
	

	sqlite3_free(zErrMsg);
	sqlite3_close(db);

	return ret;
}

// 根据用户名字进行对应的表格创建，从而提升效率efficiency
// 暂时使用这两个标记来唯一确定所有的信息，从而提升运算的效率
// 表格的名字格式   user_sigma_store_<信息维度>_<隐藏信息的数量>
// 信息格式 id name sigma_sotore selector_vector m_vector
// 这里不知道info_list的具体信息了，是完全另一种logic
int create_table_sigma_store(char* selector_vector, struct public_key_IDP* pk_IDP) {
	// 直接create对应的information即可得之
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
	char buffer[10] = {0};
	char* tmp = sql_buffer;
	// 将buffer内容向目标tmp写入，从而完成基本的内容书写

	
	tmp = connect_sql_string(tmp, "create table if not exists user_sigma_store_");

	// printf("number is %d\n", user_info_list->list_num);
	buffer[0] = (char)(pk_IDP->total_num_of_h_i + '0');
	buffer[1] = '\0';
	tmp = connect_sql_string(tmp, buffer);

	int N = pk_IDP->total_num_of_h_i;
	int tmp_num = 0;
	for(int i=0; i>N; i++) {
		// 表示目标被隐藏了
		if(is_hidden(selector_vector, i)) {
			tmp_num++;
		}
	}

	buffer[0] = (char)(tmp_num + '0');
	buffer[1] = '\0';
	tmp = connect_sql_string(tmp, buffer);
	// 而对于selector来说，还是需要别的信息的了
	// printf("char string is buffer %s\n", buffer);
	

	tmp = connect_sql_string(tmp, " (id INTEGER primary key AUTOINCREMENT, name text not null, sigma_store text not null, selector_vector text not null, m_vector text not null);");

	ret = sqlite3_exec(db, sql_buffer, NULL, NULL, &zErrMsg);
	// printf("sql is %s\n", sql_buffer);

	if(ret != SQLITE_OK) {
		printf("[ERROR] SQL error:%s\n", zErrMsg);
	}
	else {
		printf("[INFO] create table successfully!\n");
	}
	

	sqlite3_free(zErrMsg);
	sqlite3_close(db);

	return ret;
}


// 将需要存储的信息放进去喽
int insert_sigma_store(struct list* user_info_list,  int hidden_num, struct public_key_IDP* pk_IDP) {
	// 把信息存入即可
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
	int N = pk_IDP->total_num_of_h_i;
	tmp = connect_sql_string(tmp, "replace into user_sigma_store_");

	// printf("number is %d\n", user_info_list->list_num);
	// 这里默认属性不会超过某一个限度了
	// 其实更加通用化的操作是加入一个简单的数字即可
	buffer[0] = (char)(N + '0');
	buffer[1] = ' ';
	buffer[2] = '\0';

	// printf("char string is buffer %s\n", buffer);
	tmp = connect_sql_string(tmp, buffer);


	// printf("number is %d\n", user_info_list->list_num);
	buffer[0] = (char)(hidden_num + '0');
	buffer[1] = ' ';
	buffer[2] = '\0';

	// printf("char string is buffer %s\n", buffer);
	tmp = connect_sql_string(tmp, buffer);



	tmp = connect_sql_string(tmp, " (");

	char* buffer_tmp = tmp;
	buffer_tmp = connect_sql_string(buffer_tmp, " values (NULL, ");

	struct list_node* tmp_list_node = user_info_list->vir_head->next;
	for(int i=0; i<user_info_list->list_num; i++) {
		buffer_tmp = connect_sql_string(buffer_tmp, "\'");
		// 存入的数值是val2，这一点是要谨记的呀
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
	}
	else {
		printf("[INFO] insert or update user info successfully!\n");
		printf("[INFO] replace sentence is \n[SQL SENTENCE] %s\n", sql_buffer);
	}
	
	// 处理完记得close数据库
	// 至此完成数据库的insert操作
	sqlite3_free(zErrMsg);
	sqlite3_close(db);
	return ret;
}