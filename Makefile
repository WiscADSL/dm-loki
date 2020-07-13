obj-m +=dm-loki.o

dm-loki-objs += dm-loki-main.o dm-loki-fault-list.o dm-loki-handle-messages.o dm-loki-log.o twobitseq.o

all:
	@make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

.PHONY: clean
clean:
	@make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	@rm -f *.o.ur-safe
	@make -f tests.makefile clean

.PHONY: insert
insert: all
	-sudo rmmod dm-loki.ko
	-sudo insmod ./dm-loki.ko

.PHONY: testdeps
testdeps:
	@make -f tests.makefile testdeps

.PHONY: test
test: testdeps insert
	-@make -f tests.makefile run_tests
	-@make -f tests.makefile teardown
	-@make -f tests.makefile summary

.PHONY: test_small_logimg
test_small_logimg: testdeps insert
	-@make -f tests.makefile test_small_logimg
	-@make -f tests.makefile teardown

.PHONY: minitest
minitest: testdeps insert
	-@make -f tests.makefile run_minitests
	-@make -f tests.makefile teardown

.PHONY: interesting
interesting: testdeps insert
	-@make -f tests.makefile interesting
	-@make -f tests.makefile teardown
