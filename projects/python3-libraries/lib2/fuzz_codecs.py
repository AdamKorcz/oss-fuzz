from fuzz_dp import FuzzedDataProvider
import codecs
import io

DECODERS = [
    "utf-7", "shift_jis", "euc-jp", "gb2312", "big5", "iso-2022-jp",
    "euc-kr", "gb18030", "big5hkscs", "charmap", "ascii", "latin-1",
    "cp1252", "unicode_escape", "raw_unicode_escape", "utf-16", "utf-32",
]

ENCODERS = [
    "shift_jis", "euc-jp", "gb2312", "big5", "iso-2022-jp", "euc-kr",
    "gb18030", "big5hkscs", "unicode_escape", "raw_unicode_escape",
    "utf-7", "utf-8", "utf-16", "utf-16-le", "utf-16-be", "utf-32",
    "latin-1", "ascii", "charmap",
]

INC_DEC_CODECS = ["shift_jis", "gb18030", "utf-16"]
INC_ENC_CODECS = ["shift_jis", "utf-8"]

def op_decode(fdp):
    codec = fdp.PickValueInList(DECODERS)
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    codecs.decode(data, codec, 'replace')

def op_encode(fdp):
    codec = fdp.PickValueInList(ENCODERS)
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
    if n == 0:
        return
    s = fdp.ConsumeUnicode(n)
    codecs.encode(s, codec, 'replace')

def op_incremental_decode(fdp):
    codec = fdp.PickValueInList(INC_DEC_CODECS)
    split = fdp.ConsumeIntInRange(0, fdp.remaining_bytes())
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    decoder = codecs.getincrementaldecoder(codec)('replace')
    decoder.decode(data[:split])
    decoder.decode(data[split:], True)
    decoder.getstate()
    decoder.reset()

def op_incremental_encode(fdp):
    codec = fdp.PickValueInList(INC_ENC_CODECS)
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
    if n == 0:
        return
    s = fdp.ConsumeUnicode(n)
    split = fdp.ConsumeIntInRange(0, len(s))
    encoder = codecs.getincrementalencoder(codec)('replace')
    encoder.encode(s[:split])
    encoder.reset()
    encoder.encode(s[split:])
    encoder.getstate()

def op_stream(fdp):
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    bio = io.BytesIO(data)
    reader = codecs.getreader('utf-8')(bio, 'replace')
    reader.read()

def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x100000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    op = fdp.ConsumeIntInRange(0, 4)
    try:
        if op == 0:
            op_decode(fdp)
        elif op == 1:
            op_encode(fdp)
        elif op == 2:
            op_incremental_decode(fdp)
        elif op == 3:
            op_incremental_encode(fdp)
        else:
            op_stream(fdp)
    except Exception:
        pass
