from fuzz_dp import FuzzedDataProvider
import zlib
import bz2
import lzma

WBITS_CHOICES = [-15, 0, 15, 31, 47]

def op_zlib_decompress(fdp):
    wbits = fdp.PickValueInList(WBITS_CHOICES)
    use_zdict = fdp.ConsumeBool()
    zdict_size = fdp.ConsumeIntInRange(1, 32768)
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    kwargs = {}
    if use_zdict and len(data) > zdict_size:
        kwargs['zdict'] = data[:zdict_size]
        data = data[zdict_size:]
    dobj = zlib.decompressobj(wbits, **kwargs)
    dobj.decompress(data, 1048576)
    if len(data) % 2 == 0:
        dobj.flush()
    if len(data) % 3 == 0:
        copy_obj = dobj.copy()
        copy_obj.decompress(data, 1048576)

def op_zlib_compress(fdp):
    level = fdp.ConsumeIntInRange(0, 9)
    use_obj = fdp.ConsumeBool()
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
    if n == 0:
        return
    data = fdp.ConsumeBytes(n)
    if use_obj:
        cobj = zlib.compressobj(level)
        cobj.compress(data)
        if len(data) % 2 == 0:
            copy_obj = cobj.copy()
            copy_obj.flush()
        cobj.flush()
    else:
        zlib.compress(data, level)

def op_zlib_checksum(fdp):
    use_crc = fdp.ConsumeBool()
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    if use_crc:
        zlib.crc32(data)
    else:
        zlib.adler32(data)

def op_bz2(fdp):
    do_compress = fdp.ConsumeBool()
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
    if n == 0:
        return
    data = fdp.ConsumeBytes(n)
    if do_compress:
        bz2.compress(data)
    else:
        dobj = bz2.BZ2Decompressor()
        dobj.decompress(data, 1048576)

def op_lzma_decompress(fdp):
    formats = [lzma.FORMAT_AUTO, lzma.FORMAT_XZ, lzma.FORMAT_ALONE, lzma.FORMAT_RAW]
    fmt = fdp.PickValueInList(formats)
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
    if n == 0:
        return
    data = fdp.ConsumeBytes(n)
    kwargs = {'format': fmt, 'memlimit': 16 * 1024 * 1024}
    if fmt == lzma.FORMAT_RAW:
        kwargs['filters'] = [{'id': lzma.FILTER_LZMA2}]
        del kwargs['memlimit']
    dobj = lzma.LZMADecompressor(**kwargs)
    dobj.decompress(data, 1048576)

def op_lzma_compress(fdp):
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
    if n == 0:
        return
    data = fdp.ConsumeBytes(n)
    lzma.compress(data)

def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x100000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    op = fdp.ConsumeIntInRange(0, 5)
    try:
        if op == 0:
            op_zlib_decompress(fdp)
        elif op == 1:
            op_zlib_compress(fdp)
        elif op == 2:
            op_zlib_checksum(fdp)
        elif op == 3:
            op_bz2(fdp)
        elif op == 4:
            op_lzma_decompress(fdp)
        else:
            op_lzma_compress(fdp)
    except Exception:
        pass
