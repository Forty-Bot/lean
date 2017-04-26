ccflags-y := -I$(src)/../include
obj-m := lean.o
lean-y := super.o inode.o util.o file.o dir.o
MY_CFLAGS += -g -DDEBUG
ccflags-y += ${MY_CFLAGS}
CC += ${MY_CFLAGS}

default:
	make -C /lib/modules/`uname -r`/build M=$$PWD modules

.PHONY: clean
clean:
	make -C /lib/modules/`uname -r`/build M=$$PWD clean

.PHONY: install
install:
	make -C /lib/modules/`uname -r`/build M=$$PWD modules_install
