#!/bin/sh

make

lsmod | grep rfc8250
if [ $? -eq 0 ]; then
    sudo rmmod rfc8250
fi

sudo insmod rfc8250.ko
