BUILD_DIR = ./build
CC = gcc
# 使用gcc进行链接link
LD = gcc
LIB = -I data_structure/ -I lib/ -I main/ -I test/ -I config/ -I crypto_algorithm/ -I thread_pool/
# -fno-builtin 防止和系统函数冲突
# -fno-stack_protector -fstack-protector-all(启用堆栈保护)
CFLAGS = $(LIB) -c -g -fstack-protector-all

LDFLAGS = -g -e main
OBJS = $(BUILD_DIR)/main.o \
	$(BUILD_DIR)/test.o \
	$(BUILD_DIR)/list_own.o \
	$(BUILD_DIR)/read_config.o \
	$(BUILD_DIR)/basic_algorithm.o \
	$(BUILD_DIR)/thread_pool.o

ALL_DEPENDENCIES_H = config/read_config.h \
	crypto_algorithm/basic_algorithm.h \
	data_structure/all_def.h data_structure/list_own.h \
	main/global.h main/main.h main/stdint_p.h \
	test/test.h \
	thread_pool/thread_pool.h

OUTSIDE_LIB = -L. -l gmp -l pbc -l crypto -pthread

## compile for c code ##

$(BUILD_DIR)/test.o: test/test.c $(ALL_DEPENDENCIES_H)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/list_own.o: data_structure/list_own.c $(ALL_DEPENDENCIES_H)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/read_config.o: config/read_config.c $(ALL_DEPENDENCIES_H)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/basic_algorithm.o: crypto_algorithm/basic_algorithm.c $(ALL_DEPENDENCIES_H)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/thread_pool.o: thread_pool/thread_pool.c $(ALL_DEPENDENCIES_H)
	$(CC) $(CFLAGS) -D THPOOL_DEBUG $< -o $@

$(BUILD_DIR)/main.o: main/main.c $(ALL_DEPENDENCIES_H)
	$(CC) $(CFLAGS) $< -o $@

## link all files ##
$(BUILD_DIR)/IDP_kernel.bin: $(OBJS)
	$(LD) $(LDFLAGS) $^ -o $@ $(OUTSIDE_LIB)

## make all files
all:$(BUILD_DIR)/IDP_kernel.bin
	echo "compile and link successfully!"

clean:
	rm build/*.o
	rm build/*.bin