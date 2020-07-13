CC = gcc
CFLAGS = -Wall -Werror -Wextra

twobitseq_test.out: twobitseq.c twobitseq_test.c twobitseq.h
	$(CC) $(CFLAGS) -DTBS_TEST_MODE_ON=1 twobitseq_test.c twobitseq.c -o twobitseq_test.out

testutils/write_to_dev.out: testutils/write_to_dev.c
	$(CC) $(CFLAGS) testutils/write_to_dev.c -o testutils/write_to_dev.out

testutils/dump_img.out: testutils/dump_img.c
	$(CC) $(CFLAGS) testutils/dump_img.c -o testutils/dump_img.out

testutils/read_block.out: testutils/read_block.c
	$(CC) $(CFLAGS) testutils/read_block.c -o testutils/read_block.out

testutils/write_block.out: testutils/write_block.c
	$(CC) $(CFLAGS) testutils/write_block.c -o testutils/write_block.out


.PHONY: clean
clean:
	@rm -f twobitseq_test.out testutils/*.out errors.log test.img log.img

.PHONY: testdeps
testdeps: twobitseq_test.out testutils/write_to_dev.out testutils/dump_img.out

.PHONY: run_minitests
run_minitests: testutils/read_block.out testutils/write_block.out
	@rm -f test.img log.img
	@touch test.img log.img
	@fallocate -z -l 1G test.img
	@fallocate -z -l 1G log.img
	@sudo losetup loop0 test.img
	@sudo losetup loop1 log.img
	@sudo dmsetup create errdev0 --table '0 80 loki /dev/loop0 mytestid /dev/loop1 0 2097152'
	sleep 5
	sudo testutils/write_block.out /dev/mapper/errdev0 1 b
	@sudo dmsetup message errdev0 0 'enable_sector_log'
	sleep 3
	sudo testutils/read_block.out /dev/mapper/errdev0 1
	sudo testutils/write_block.out /dev/mapper/errdev0 1 c
	sudo testutils/read_block.out /dev/mapper/errdev0 1

.PHONY: interesting
interesting: testutils/write_block.out
# Just writing out 1 block causes so many reads
	@rm -f test.img log.img
	dd if=/dev/zero of=test.img bs=512 count=1024
	dd if=/dev/zero of=log.img bs=512 count=1024
	sudo losetup loop0 test.img
	sudo losetup loop1 log.img
	sudo dmsetup create errdev0 --table '0 1024 loki /dev/loop0 mytestid /dev/loop1 0 1024'
	sudo dmsetup message errdev0 0 'enable_sector_log'
	sudo testutils/write_block.out /dev/mapper/errdev0 1 b

.PHONY: test_small_logimg
test_small_logimg: testutils/write_block.out
	@rm -f test.img log.img
	@dd if=/dev/zero of=test.img bs=512 count=80
	@dd if=/dev/zero of=log.img bs=512 count=12
	@sudo losetup loop0 test.img
	@sudo losetup loop1 log.img
	@sudo dmsetup create errdev0 --table '0 80 loki /dev/loop0 mytestid /dev/loop1 0 12'
	@sudo dmsetup message errdev0 0 'enable_sector_log'
	sudo testutils/write_block.out /dev/mapper/errdev0 0 a
	sudo testutils/write_block.out /dev/mapper/errdev0 1 b
	sudo testutils/write_block.out /dev/mapper/errdev0 2 c

.PHONY: run_tests
run_tests: twobitseq_test.out testutils/write_to_dev.out
	@rm -f errors.log test.img log.img

# setup
# @dd if=/dev/zero of=test.img bs=512 count=2097152
# @dd if=/dev/zero of=log.img bs=512 count=2097152
	@touch test.img log.img
	@fallocate -z -l 1G test.img
	@fallocate -z -l 1G log.img

	@sudo losetup loop0 test.img
	@sudo losetup loop1 log.img
	@sudo dmsetup create errdev0 --table '0 80 loki /dev/loop0 mytestid /dev/loop1 0 2097152'

# test twobitseq lib
	./twobitseq_test.out

# test messages
	@(sudo dmsetup message errdev0 0 'Test message' && (echo "failed to catch bad message" >> errors.log)) || echo "Ignore above error. It meant to do that"
	@sudo dmsetup message errdev0 0 'add_fault_item 5 6 X'
	@sudo dmsetup message errdev0 0 'add_fault_item 20 25 WWFWX'
	@(sudo dmsetup message errdev0 0 'add_fault_item 28 25'&& (echo "accepted end > start!!" >> errors.log)) || echo "Ignore above error. It meant to do that"
	@sudo dmsetup message errdev0 0 'dump_fault_list'
	@sudo dmsetup message errdev0 0 'del_fault_item 5 6'
	@(sudo dmsetup message errdev0 0 'del_fault_item 5 6' && (echo "no indication that fault item wasn't removed" >> errors.log)) || echo "Ignore above error. It meant to do that"
	@sudo dmsetup message errdev0 0 'dump_fault_list'
	@sudo dmsetup message errdev0 0 'del_fault_item 20 25'
	@sudo dmsetup message errdev0 0 'dump_fault_list'

# test image after writes
# configuring it to fail for a few sectors
	@sudo dmsetup message errdev0 0 'enable_sector_log'
	@sudo dmsetup message errdev0 0 'set_log_tag test1'
	@sudo dmsetup message errdev0 0 'add_fault_item 10 12 X'
	@sudo dmsetup message errdev0 0 'add_fault_item 20 25 X'
	@sudo dmsetup message errdev0 0 'add_fault_item 37 38 X'
	sudo ./testutils/write_to_dev.out /dev/mapper/errdev0 a 0 7
# tests with an exact hole
	sudo ./testutils/write_to_dev.out /dev/mapper/errdev0 b 37 38
# tests with a hole in the beginning
	sudo ./testutils/write_to_dev.out /dev/mapper/errdev0 c 37 45
# tests with a hole at the end
	sudo ./testutils/write_to_dev.out /dev/mapper/errdev0 d 34 38
# tests with a hole perfectly in the middle
	sudo ./testutils/write_to_dev.out /dev/mapper/errdev0 e 8 15
# tests with end in the middle of fault hole
	sudo ./testutils/write_to_dev.out /dev/mapper/errdev0 f 18 22
# tests with beginning in the middle of a fault hole
	sudo ./testutils/write_to_dev.out /dev/mapper/errdev0 g 23 28
	
# tests where we fail, allow one in the middle, and then allow all later
	@sudo dmsetup message errdev0 0 'set_log_tag test2'
	@sudo dmsetup message errdev0 0 'add_fault_item 64 69 FFWFA'
	sudo ./testutils/write_to_dev.out /dev/mapper/errdev0 h 60 69
	sudo ./testutils/write_to_dev.out /dev/mapper/errdev0 i 64 69
	sudo ./testutils/write_to_dev.out /dev/mapper/errdev0 j 62 68
	sudo ./testutils/write_to_dev.out /dev/mapper/errdev0 k 63 68
	sudo ./testutils/write_to_dev.out /dev/mapper/errdev0 l 64 69

# tests where we fail one in the middle among other writes, and fail all later
	@sudo dmsetup message errdev0 0 'set_log_tag test3'
	@sudo dmsetup message errdev0 0 'add_fault_item 72 79 WFWX'
	sudo ./testutils/write_to_dev.out /dev/mapper/errdev0 m 70 79
	sudo ./testutils/write_to_dev.out /dev/mapper/errdev0 n 72 79
	sudo ./testutils/write_to_dev.out /dev/mapper/errdev0 o 72 79
	sudo ./testutils/write_to_dev.out /dev/mapper/errdev0 p 75 79
	sudo ./testutils/write_to_dev.out /dev/mapper/errdev0 q 76 79

# tests to disable writes
	@sudo dmsetup message errdev0 0 'disable_dev'
	sudo ./testutils/write_to_dev.out /dev/mapper/errdev0 r 70 79
	sudo ./testutils/write_to_dev.out /dev/mapper/errdev0 s 55 57
	@sudo dmsetup message errdev0 0 'enable_dev'
	sudo ./testutils/write_to_dev.out /dev/mapper/errdev0 t 55 57

# TODO test reads?


.PHONY: teardown
teardown:
	@sudo dmsetup remove errdev0
	@sudo losetup -d /dev/loop0
	@sudo losetup -d /dev/loop1

.PHONY: summary
summary: testutils/dump_img.out
	@echo "Image contents:"
	@./testutils/dump_img.out test.img
	@(./testutils/compare_images.py test.img expected_img) || (echo "image mismatch" >> errors.log)
	@(test -s errors.log && echo "Tests Failed! Check errors.log") || echo "Tests Passed!"
