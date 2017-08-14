UNAME := $(shell uname -r)
BUILD_PATH := /lib/modules/$(UNAME)/build
ccflags-y := -I$(src)/../include
obj-m := lean.o
lean-y := super.o inode.o util.o file.o dir.o alloc.o
MY_CFLAGS += -g -DDEBUG
ccflags-y += ${MY_CFLAGS}
CC += ${MY_CFLAGS}

default:
	make -C $(BUILD_PATH) M=$$PWD modules

.PHONY: clean
clean:
	make -C $(BUILD_PATH) M=$$PWD clean

.PHONY: install
install:
	make -C $(BUILD_PATH) M=$$PWD modules_install
