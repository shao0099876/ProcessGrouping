obj-m += process_grouping.o
process_grouping.o := -O0
all:
	make -C /root/kernel M=$(PWD) modules
clean:
	make -C /root/kernel M=$(PWD) clean