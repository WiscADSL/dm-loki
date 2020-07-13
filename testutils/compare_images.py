#!/usr/bin/env python

import hashlib
import sys

with open(sys.argv[1], 'rb') as a, open(sys.argv[2], 'rb') as b:
    hex_a = hashlib.md5(a.read(80 * 512)).hexdigest()
    hex_b = hashlib.md5(b.read(80 * 512)).hexdigest()
    assert hex_a == hex_b, "Image mismatch!"
