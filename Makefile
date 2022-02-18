obj-m += hwbreak.o
all:
	make -C /msm M=$(PWD) modules
clean:
	make -C /msm M=$(PWD) clean
