BUILD_DIR = ./build
CC = gcc
# 使用gcc进行链接link
LD = gcc
LIB = -I data_structure/ -I lib/ -I main/ -I test/ -I config/ -I crypto_algorithm/ -I thread_pool/ -I network_wrap/ -I database/Dao \
	-I database/sqlite
# -fno-builtin 防止和系统函数冲突
# -fno-stack_protector -fstack-protector-all(启用堆栈保护)
CFLAGS = $(LIB) -c -g -fstack-protector-all

# LDFLAGS = -g -e main
LDFLAGS = -g
OBJS = $(BUILD_DIR)/main.o \
	$(BUILD_DIR)/test.o \
	$(BUILD_DIR)/list_own.o \
	$(BUILD_DIR)/read_config.o \
	$(BUILD_DIR)/basic_algorithm.o \
	$(BUILD_DIR)/thread_pool.o \
	$(BUILD_DIR)/Elliptic_Curve.o \
	$(BUILD_DIR)/server_api.o \
	$(BUILD_DIR)/structure_to_bytes.o \
	\
	$(BUILD_DIR)/database/sqlite.o \
	$(BUILD_DIR)/sqlite3_use.o \
	$(BUILD_DIR)/userinfo_dao.o

ALL_DEPENDENCIES_H = config/read_config.h config/Elliptic_Curve.h\
	crypto_algorithm/basic_algorithm.h crypto_algorithm/structure_to_bytes.h \
	data_structure/all_def.h data_structure/list_own.h \
	main/global.h main/main.h main/stdint_p.h \
	test/test.h \
	thread_pool/thread_pool.h \
	network_wrap/server_api.h network_wrap/protocol_structure.h \
	database/sqlite/sqlite.h \
	database/Dao/sqlite3_use.h database/Dao/userinfo_dao.h \
	main/server_config.h

# OUTSIDE_LIB = -L. -l gmp -l pbc -l crypto -pthread  -ldl参数专门是给sqlite编译用的
OUTSIDE_LIB = -L. -l gmp -l pbc -l crypto -pthread -ldl

## compile for c code ##

$(BUILD_DIR)/test.o: test/test.c $(ALL_DEPENDENCIES_H)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/list_own.o: data_structure/list_own.c $(ALL_DEPENDENCIES_H)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/read_config.o: config/read_config.c $(ALL_DEPENDENCIES_H)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/Elliptic_Curve.o: config/Elliptic_Curve.c $(ALL_DEPENDENCIES_H)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/server_api.o: network_wrap/server_api.c $(ALL_DEPENDENCIES_H)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/basic_algorithm.o: crypto_algorithm/basic_algorithm.c $(ALL_DEPENDENCIES_H)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/structure_to_bytes.o: crypto_algorithm/structure_to_bytes.c $(ALL_DEPENDENCIES_H)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/thread_pool.o: thread_pool/thread_pool.c $(ALL_DEPENDENCIES_H)
	$(CC) $(CFLAGS) -D THPOOL_DEBUG $< -o $@

$(BUILD_DIR)/database/sqlite.o: database/sqlite/sqlite.c $(ALL_DEPENDENCIES_H)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/sqlite3_use.o: database/Dao/sqlite3_use.c $(ALL_DEPENDENCIES_H)
	$(CC) $(CFLAGS) $< -o $@
# 数据库的可持久化处理操作
$(BUILD_DIR)/userinfo_dao.o: database/Dao/userinfo_dao.c $(ALL_DEPENDENCIES_H)
	$(CC) $(CFLAGS) $< -o $@
# Elliptic_Curve.h


$(BUILD_DIR)/main.o: main/main.c $(ALL_DEPENDENCIES_H)
	$(CC) $(CFLAGS) $< -o $@

## link all files ##
$(BUILD_DIR)/Server.bin: $(OBJS)
	$(LD) $(LDFLAGS) $^ -o $@ $(OUTSIDE_LIB)

## make all files
all:$(BUILD_DIR)/Server.bin
	echo "compile and link successfully!"
	./build/Server.bin
clean:
	rm build/*.o
	rm build/*.bin