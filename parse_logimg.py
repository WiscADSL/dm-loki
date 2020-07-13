import struct

class Flags(object):
    SEQUENCE = (
        "flush", "fua", "read", "write", "sync",
        "discard", "has_msg", "is_bio", "error", "has_data",
    )

    def __init__(self, flags):
        self.flags = flags

    def __getattr__(self, key):
        try:
            idx = self.SEQUENCE.index(key)
        except ValueError:
            raise AttributeError(key)

        idxval = 1 << idx
        return bool(self.flags & idxval)

    def __str__(self):
        s = []
        for f in self.SEQUENCE:
            s.append(f'{f}={getattr(self, f)}')

        return ','.join(s)

    __unicode__ = __repr__ = __str__

class Header(object):
    def __init__(self, bytearr):
        assert len(bytearr) == 512
        unpacked = struct.unpack(f"<4Q{512-32}s", bytearr)
        self.magic, self.sector, self.size, self.flags, self.msg = unpacked
        self.flags = Flags(self.flags)

    def __str__(self):
        return f'sector={self.sector},size={self.size},flags=({self.flags})'

    __unicode__ = __repr__ = __str__

class Superblock(object):
    def __init__(self, bytearr):
        assert len(bytearr) == 512
        unpacked = struct.unpack(f"<4Q{512-32}s", bytearr)
        self.magic, self.num_bios, self.last_sector, self.num_missing, junk = unpacked

    def __str__(self):
        return f'num_bios={self.num_bios},last_sector={self.last_sector},num_missing={self.num_missing}'

    __unicode__ = __repr__ = __str__

logimg = []

with open("log.img", "rb") as fp:
    sb = Superblock(fp.read(512))
    i = 0
    logimg.append(sb)
    print(sb)
    while i < sb.num_bios:
        i += 1
        data = fp.read(512)
        header = Header(data)

        logimg.append(header)
        if header.size != 0:
            # add data blocks
            data = fp.read(header.size)
            logimg.append(data)
