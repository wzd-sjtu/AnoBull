BUILD_DIR = ./build
CC = gcc
LD = gcc
LIB = -I IDP/ -I RP/ -I CLIENT/ -I lib/
# -fno-builtin 防止和系统函数冲突
# -fno-stack_protector -fstack-protector-all(启用堆栈保护)
CFLAGS = $(LIB) -c -g -fstack-protector-all

LDFLAGS = -g -e main
OBJS = $(BUILD_DIR)/main.o $(BUILD_DIR)/IDP_init.o $(BUILD_DIR)/CLIENT_compute.o \
		$(BUILD_DIR)/RP_verify.o $(BUILD_DIR)/IDP_audit.o \
		$(BUILD_DIR)/struct_to_from_bytes.o

ALL_DEPENDENCIES_H = IDP/IDP_init.h CLIENT/CLIENT_compute.h RP/RP_verify.h \
		IDP/IDP_audit.h lib/struct_to_from_bytes.h

OUTSIDE_LIB = -L. -l gmp -l pbc -l crypto
## compile for c code ##
$(BUILD_DIR)/main.o: kernel/main.c $(ALL_DEPENDENCIES_H)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/IDP_init.o: IDP/IDP_init.c $(ALL_DEPENDENCIES_H)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/CLIENT_compute.o: CLIENT/CLIENT_compute.c $(ALL_DEPENDENCIES_H)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/RP_verify.o: RP/RP_verify.c $(ALL_DEPENDENCIES_H)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/IDP_audit.o: IDP/IDP_audit.c $(ALL_DEPENDENCIES_H)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/struct_to_from_bytes.o: lib/struct_to_from_bytes.c $(ALL_DEPENDENCIES_H)
	$(CC) $(CFLAGS) $< -o $@
## link all files ##
$(BUILD_DIR)/kernel.bin: $(OBJS)
	$(LD) $(LDFLAGS) $^ -o $@ $(OUTSIDE_LIB)

all:$(BUILD_DIR)/kernel.bin
	echo "write successfully!"

clean:
	rm build/*.o
	rm build/*.bin