ccflags-y := -I$(src)/../include
obj-m := lean.o

default:
	make -C /lib/modules/`uname -r`/build M=$$PWD modules

.PHONY: clean
clean:
	make -C /lib/modules/`uname -r`/build M=$$PWD clean

.PHONY: install
install:
	make -C /lib/modules/`uname -r`/build M=$$PWD modules_install
