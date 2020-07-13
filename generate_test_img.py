#!/usr/bin/env python3

disk = ['\0'] * (80 * 512)

def mark(buf, c, start, end):
    i = start * 512
    end = (end + 1) * 512
    while i < end:
        buf[i] = c
        i += 1

# always fail 10-12, 20-25, 37-38

mark(disk, 'a', 0, 7)

# mark(disk, 'b', 37, 38)

# mark(disk, 'c', 37, 45)
mark(disk, 'c', 39, 45)

# mark(disk, 'd', 34, 38)
mark(disk, 'd', 34, 36)

# mark(disk, 'e', 8, 15)
mark(disk, 'e', 8, 9)
mark(disk, 'e', 13, 15)

#mark(disk, 'f', 18, 22)
mark(disk, 'f', 18, 19)

#mark(disk, 'g', 23, 28)
mark(disk, 'g', 26, 28)

# Fail 64 69 FFWFA

# mark(disk, 'h', 60, 69)
mark(disk, 'h', 60, 63) # FWFA

#mark(disk, 'i', 64, 69) # WFA

mark(disk, 'j', 62, 68) # FA

# mark(disk, 'k', 63, 68)
mark(disk, 'k', 63, 63) # A
mark(disk, 'l', 64, 69)

# Fail 72 79 WFWX
mark(disk, 'm', 70, 79) # FWX

mark(disk, 'n', 72, 79) # WX

mark(disk, 'o', 72, 79) # X

# mark(disk, 'p', 75, 79)
# mark(disk, 'q', 76, 79)

# disable dev
# mark(disk, 'r', 70, 79)
# mark(disk, 's', 55, 57)

# enable dev
mark(disk, 't', 55, 57)

with open("expected_img", 'wb') as fp:
    fp.write(''.join(disk).encode())
