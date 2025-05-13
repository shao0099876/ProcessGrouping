obj-m += process_grouping.o
all:
	make -C /root/kernel M=$(PWD) modules
clean:
	make -C /root/kernel M=$(PWD) clean
