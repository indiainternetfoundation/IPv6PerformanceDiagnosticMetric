obj-m += rfc8250.o
linux-version := $(shell uname -r)

all:
	make -C /lib/modules/${linux-version}/build M=$(PWD) modules

clean:
	make -C /lib/modules/${linux-version}/build M=$(PWD) clean

test:
	sudo dmesg -C
	sudo insmod rfc8250.ko
	sleep 10
	sudo rmmod rfc8250.ko
	dmesg
