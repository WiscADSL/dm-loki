# TODO maybe try using fallocate?
rm -f test.img log.img

dd if=/dev/zero of=test.img bs=512 count=2097152
dd if=/dev/zero of=log.img bs=512 count=2097152

mkfs -t ext4 test.img
sudo losetup /dev/loop0 test.img
sudo losetup /dev/loop1 log.img

mkdir -p /tmp/errmount

# mount once, let all setup stuff happen
sudo mount /dev/loop0 /tmp/errmount
sudo umount /tmp/errmount

sleep 5

sudo dmsetup create errdev0 --table '0 2097152 loki /dev/loop0 mytestid /dev/loop1 0 2097152'
sudo mount /dev/mapper/errdev0 /tmp/errmount
sudo chown `id -u`:`id -g` /tmp/errmount
sleep 5

sudo dmsetup message errdev0 0 'enable_sector_log'
head -c 4096 /dev/zero |tr '\0' 'a' > /tmp/errmount/a.txt
head -c 4096 /dev/zero |tr '\0' 'b' > /tmp/errmount/a.txt
head -c 4096 /dev/zero |tr '\0' 'c' > /tmp/errmount/a.txt
head -c 4096 /dev/zero |tr '\0' 'd' > /tmp/errmount/a.txt
sync -d /tmp/errmount/a.txt
head -c 4096 /dev/zero |tr '\0' 'e' > /tmp/errmount/b.txt
head -c 4096 /dev/zero |tr '\0' 'f' > /tmp/errmount/b.txt
head -c 4096 /dev/zero |tr '\0' 'g' > /tmp/errmount/b.txt
head -c 4096 /dev/zero |tr '\0' 'h' > /tmp/errmount/b.txt
sync -d /tmp/errmount/b.txt
head -c 12288 /dev/zero | tr '\0' 'x' > /tmp/errmount/c.txt
sync -d /tmp/errmount/c.txt

sudo umount /tmp/errmount
sudo dmsetup remove errdev0
sudo losetup -d /dev/loop0
sudo losetup -d /dev/loop1
