# dm-loki
Device mapper target allowing deterministic fault injection

# Installation

`dm-loki` is a loadable kernel module.

```bash
git clone git@github.com:algrebe/dm-loki.git
cd dm-loki
make test

sudo rmmod dm-loki.ko
sudo insmod ./dm-loki.ko
```

Please take a look at `tests.makefile` for examples. 
