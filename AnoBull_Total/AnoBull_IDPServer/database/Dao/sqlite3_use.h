#ifndef __SQLITE3_USE_H
#define __SQLITE3_USE_H
#include <stdio.h>
#include <sqlite.h>
#include <string.h>
#include <errno.h>
// #include "database_config.h"
#include "sqlite3_use.h"
#include "global.h"
#include "server_config.h"

int sqlite_init(const char *db_path);
int create_table_by_list(struct list* user_info_list);
// int create_table_sigma_c();
int create_table_sigma_c(struct list* user_info_list);
int insert_user_info_by_list(struct list* user_info_list);

int create_table_sigma_store(char* selector_vector, struct public_key_IDP* pk_IDP);
int insert_sigma_store(struct list* sigma_store_list,  int hidden_num, struct public_key_IDP* pk_IDP);

#endif