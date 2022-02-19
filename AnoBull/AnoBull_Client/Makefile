BUILD_DIR = ./build
CC = gcc
# 使用gcc进行链接link
LD = gcc
LIB = -I data_structure/ -I main/ -I crypto_algorithm/ -I network_wrap/
# -fno-builtin 防止和系统函数冲突
# -fno-stack_protector -fstack-protector-all(启用堆栈保护)
CFLAGS = $(LIB) -c -g -fstack-protector-all

# LDFLAGS = -g -e main
LDFLAGS = -g
OBJS = $(BUILD_DIR)/main.o \
	$(BUILD_DIR)/list_own.o \
	# $(BUILD_DIR)/basic_algorithm.o 

ALL_DEPENDENCIES_H = data_structure/all_def.h data_structure/list_own.h \
	main/main.h

OUTSIDE_LIB = -L. -l gmp -l pbc -l crypto -pthread

## compile for c code ##

$(BUILD_DIR)/list_own.o: data_structure/list_own.c $(ALL_DEPENDENCIES_H)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/main.o: main/main.c $(ALL_DEPENDENCIES_H)
	$(CC) $(CFLAGS) $< -o $@

## link all files ##
$(BUILD_DIR)/Client.bin: $(OBJS)
	$(LD) $(LDFLAGS) $^ -o $@ $(OUTSIDE_LIB)

## make all files
all:$(BUILD_DIR)/Client.bin
	echo "compile and link successfully!"
	./build/Client.bin
clean:
	rm build/*.o
	rm build/*.bin