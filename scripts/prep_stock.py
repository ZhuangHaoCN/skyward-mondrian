#!/usr/bin/env python3
"""Recut a bootimg v3 ramdisk so every LZ4 legacy block stays under 8 MiB.

lz4 -l ignores -B, so the legs are framed here: magic, then each 4 MiB of
payload as one lz4 block with its compressed length in front. lz4_flex, the
decoder skyward-bootimg uses, refuses any block over 8 MiB, which is exactly
what a stock ramdisk carrying pregzipped payloads (Magisk's two 11.7 MB apks)
produces at the default 8 MiB leg.
"""
import struct, sys

try:
    import lz4.block
except ImportError:
    sys.exit('need the lz4 python module: pip install lz4')

LEGACY_MAGIC = b'\x02\x21\x4c\x18'
MAX_BLOCK = 8 * 1024 * 1024

def decode_legacy(rd):
    out = bytearray()
    pos = 0
    first = True
    while pos + 4 <= len(rd):
        if first and rd[:4] == LEGACY_MAGIC:
            pos = 4
        first = False
        if pos + 4 > len(rd):
            break
        size = struct.unpack('<I', rd[pos:pos + 4])[0]
        pos += 4
        if size == 0 or size > len(rd) - pos:
            break
        chunk = rd[pos:pos + size]
        pos += size
        dec = None
        for guess in (8 << 20, 16 << 20, 32 << 20, 64 << 20):
            try:
                dec = lz4.block.decompress(chunk, uncompressed_size=guess)
                break
            except Exception:
                continue
        if dec is None:
            sys.exit('could not decompress a block near offset %d' % (pos - size))
        out += dec
    return bytes(out)

def encode_legacy(raw, leg):
    out = bytearray(LEGACY_MAGIC)
    biggest = 0
    blocks = 0
    for start in range(0, len(raw), leg):
        packed = lz4.block.compress(raw[start:start + leg], store_size=False)
        out += struct.pack('<I', len(packed))
        out += packed
        biggest = max(biggest, len(packed))
        blocks += 1
    return bytes(out), blocks, biggest


def cpio_entries(blob):
    """Walk a newc archive and yield (name, mode, uid, gid, mtime, nlink,
    dev, rdev, data) for each member."""
    pos = 0
    while pos + 110 <= len(blob):
        if blob[pos:pos + 6] != b'070701':
            return
        def field(offset):
            return int(blob[pos + offset:pos + offset + 8], 16)
        ino = field(6)
        mode = field(14)
        uid = field(22)
        gid = field(30)
        nlink = field(38)
        mtime = field(46)
        filesize = field(54)
        dev = (field(62), field(70))
        rdev = (field(78), field(86))
        namesize = field(94)
        name = blob[pos + 110:pos + 110 + namesize - 1].decode('utf-8', 'replace')
        pos += 110 + namesize
        pos = (pos + 3) & ~3
        data = blob[pos:pos + filesize]
        pos += filesize
        pos = (pos + 3) & ~3
        if name == 'TRAILER!!!':
            return
        yield (name, ino, mode, uid, gid, nlink, mtime, dev, rdev, data)


def cpio_header(name, ino, mode, uid, gid, nlink, mtime, filesize, dev, rdev):
    raw_name = name.encode() + b'\x00'
    fields = [ino, mode, uid, gid, nlink, mtime, filesize,
              dev[0], dev[1], rdev[0], rdev[1], len(raw_name), 0]
    header = b'070701' + b''.join(b'%08x' % (f & 0xFFFFFFFF) for f in fields)
    assert len(header) == 110, len(header)
    return header, raw_name


def cpio_build(entries):
    out = bytearray()
    for (name, ino, mode, uid, gid, nlink, mtime, dev, rdev, data) in entries:
        header, raw_name = cpio_header(name, ino, mode, uid, gid, nlink, mtime,
                                      len(data), dev, rdev)
        out += header + raw_name
        out += b'\x00' * ((-(110 + len(raw_name))) % 4)
        out += data
        out += b'\x00' * ((-len(data)) % 4)
    header, raw_name = cpio_header('TRAILER!!!', 0, 0, 0, 0, 1, 0, 0, (0, 0), (0, 0))
    out += header + raw_name
    out += b'\x00' * ((-(110 + len(raw_name))) % 4)
    return bytes(out)


# Third-party trees a phone maker never ships: TWRP keeps its fonts and
# images in twres, and this recovery also carries Magisk's install apks. Both
# go, so the ramdisk holds only what MIUI put there.
DROP_PREFIXES = ('twres', 'FFiles', 'customzip', 'magisk_prebuilt')

def main(argv):
    if len(argv) < 3:
        sys.exit('usage: prep_stock.py <stock.img> <out.img>')
    src, dst = argv[1], argv[2]
    data = open(src, 'rb').read()
    if data[:8] != b'ANDROID!':
        sys.exit('not a boot image: ' + src)
    ramdisk_size = struct.unpack('<I', data[12:16])[0]
    page = 4096
    print('page0 header, ramdisk_size =', ramdisk_size)
    raw = decode_legacy(data[page:page + ramdisk_size])
    print('payload =', len(raw), 'bytes')

    kept = []
    dropped = []
    for entry in cpio_entries(raw):
        if entry[0].startswith(DROP_PREFIXES):
            dropped.append(entry)
        else:
            kept.append(entry)
    if dropped:
        print('dropping %d entries, %d bytes (third-party trees)'
              % (len(dropped), sum(len(e[9]) for e in dropped)))
        for entry in dropped[:8]:
            print('   -', entry[0])
    raw = cpio_build(kept)
    print('filtered payload =', len(raw), 'bytes, %d entries' % len(kept))

    chosen = None
    for leg in (4 << 20, 2 << 20, 1 << 20):
        packed, blocks, biggest = encode_legacy(raw, leg)
        print('  leg %2d MiB -> %d blocks, %d bytes, biggest block %d, fits=%s'
              % (leg >> 20, blocks, len(packed), biggest, biggest <= MAX_BLOCK))
        if biggest <= MAX_BLOCK:
            chosen = packed
            break
    if chosen is None:
        sys.exit('no leg size keeps every block under 8 MiB')

    head = bytearray(data[:page])
    struct.pack_into('<I', head, 12, len(chosen))
    body = bytes(head) + chosen

    # The stock image ends in an AVB footer naming where its vbmeta sits. The
    # ramdisk just changed length, so the vbmeta moves with it: carry the blob
    # over, restate its offset and the image length the footer records, and let
    # the hashes inside go stale. skyward-pack writes a fresh unsigned footer of
    # its own, so it only needs this one to be structurally valid.
    footer = data[-64:]
    if footer[:4] != b'AVBf':
        sys.exit('stock image has no AVB footer')
    vbmeta_offset = struct.unpack('>Q', footer[20:28])[0]
    vbmeta_size = struct.unpack('>Q', footer[28:36])[0]
    vbmeta = data[vbmeta_offset:vbmeta_offset + vbmeta_size]
    if len(vbmeta) != vbmeta_size:
        sys.exit('vbmeta truncated')
    print('AVB: vbmeta at %d, %d bytes' % (vbmeta_offset, vbmeta_size))

    body = body + b'\x00' * 4096
    body = body[:((len(body) + 4095) // 4096) * 4096]
    new_vbmeta_offset = len(body)
    print('new vbmeta offset =', new_vbmeta_offset)

    new_footer = bytearray(64)
    new_footer[0:4] = b'AVBf'
    struct.pack_into('>II', new_footer, 4, 1, 0)
    struct.pack_into('>Q', new_footer, 12, new_vbmeta_offset)
    struct.pack_into('>Q', new_footer, 20, new_vbmeta_offset)
    struct.pack_into('>Q', new_footer, 28, vbmeta_size)

    image = body + vbmeta
    if len(image) > len(data) - 64:
        sys.exit('recut image %d does not fit the partition %d' % (len(image), len(data)))
    image += b'\x00' * (len(data) - 64 - len(image))
    image += bytes(new_footer)
    open(dst, 'wb').write(image)
    print('written', dst, len(image))
    print('new ramdisk_size =', len(chosen))

if __name__ == '__main__':
    main(sys.argv)
