#ifndef __READ_CONFIG_H
#define __READ_CONFIG_H
#include "all_def.h"
#include "stdio.h"
#include "string.h"
#include <dirent.h>

#define MAX_LINE_READ_CONFIG 1024


#define CONFIG_DOCUMENT_PATH "./config_doc"

struct config_structure* init_test_config();
struct config_structure* read_config_init();
#endif