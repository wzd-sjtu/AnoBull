BUILD_DIR = ./build
CC = gcc
# 使用gcc进行链接link
LD = gcc
LIB = -I data_structure/ -I lib/ -I main/ -I test/ -I config/ -I crypto_algorithm/ -I thread_pool/ -I network_wrap/
# -fno-builtin 防止和系统函数冲突
# -fno-stack_protector -fstack-protector-all(启用堆栈保护)
CFLAGS = $(LIB) -c -g

LDFLAGS = -g
OBJS = $(BUILD_DIR)/main.o \
	$(BUILD_DIR)/test.o \
	$(BUILD_DIR)/list_own.o \
	$(BUILD_DIR)/read_config.o \
	$(BUILD_DIR)/basic_algorithm.o \
	$(BUILD_DIR)/thread_pool.o \
	$(BUILD_DIR)/Elliptic_Curve.o \
	$(BUILD_DIR)/server_api.o

ALL_DEPENDENCIES_H = config/read_config.h config/Elliptic_Curve.h\
	crypto_algorithm/basic_algorithm.h \
	data_structure/all_def.h data_structure/list_own.h \
	main/global.h main/main.h main/stdint_p.h \
	test/test.h \
	thread_pool/thread_pool.h \
	network_wrap/server_api.h

OUTSIDE_LIB = -L. -l gmp -l crypto -l pbc -pthread

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

$(BUILD_DIR)/thread_pool.o: thread_pool/thread_pool.c $(ALL_DEPENDENCIES_H)
	$(CC) $(CFLAGS) -D THPOOL_DEBUG $< -o $@
# Elliptic_Curve.h


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