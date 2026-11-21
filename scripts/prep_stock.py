#!/usr/bin/env python3
"""Recut a bootimg v3 ramdisk into legs whose LZ4 blocks stay under 8 MiB."""
import struct, subprocess, os, sys

MAX_BLOCK = 8388608

def main(argv):
    src, dst = argv[1], argv[2]
    d = open(src, 'rb').read()
    if d[:8] != b'ANDROID!':
        sys.exit('not a boot image: ' + src)
    rs = struct.unpack('<I', d[12:16])[0]
    page = 4096
    rd = d[page:page + rs]
    print('page0 header, ramdisk_size =', rs)

    open('/tmp/rd_in.lz4', 'wb').write(rd)
    with open('/tmp/rd.cpio', 'wb') as f:
        subprocess.run(['lz4', '-l', '-d', '-c', '/tmp/rd_in.lz4'], stdout=f, check=True)
    cpio_size = os.path.getsize('/tmp/rd.cpio')
    print('cpio size =', cpio_size)

    best = None
    for blk in ('-B4', '-B2', '-B1'):
        with open('/tmp/rd_out.lz4', 'wb') as f:
            subprocess.run(['lz4', '-l', blk, '-9', '-c', '/tmp/rd.cpio'], stdout=f, check=True)
        size = os.path.getsize('/tmp/rd_out.lz4')
        ok, biggest = check_blocks('/tmp/rd_out.lz4', MAX_BLOCK)
        print('  %s -> %d bytes, max block %d, ok=%s' % (blk, size, biggest, ok))
        if ok:
            best = size
            break
    if best is None:
        sys.exit('no block size kept every leg under 8 MiB')

    head = bytearray(d[:page])
    struct.pack_into('<I', head, 12, best)
    new = bytes(head) + open('/tmp/rd_out.lz4', 'rb').read()
    if len(new) < len(d):
        new += b'\x00' * (len(d) - len(new))
    elif len(new) > len(d):
        sys.exit('recut image is larger than the partition: %d > %d' % (len(new), len(d)))
    open(dst, 'wb').write(new)
    print('written', dst, len(new))

def check_blocks(path, limit):
    rd = open(path, 'rb').read()
    pos = 4 if rd[:4] == b'\x02\x21\x4c\x18' else 0
    biggest = 0
    while pos + 4 <= len(rd):
        sz = struct.unpack('<I', rd[pos:pos + 4])[0]
        pos += 4
        if sz == 0 or sz > len(rd) - pos:
            break
        biggest = max(biggest, sz)
        pos += sz
    return biggest <= limit, biggest

if __name__ == '__main__':
    main(sys.argv)
