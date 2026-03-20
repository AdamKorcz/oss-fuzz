from fuzz_dp import FuzzedDataProvider
import binascii

def op_decode(fdp):
    which = fdp.ConsumeIntInRange(0, 5)
    strict = fdp.ConsumeBool()
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    if which == 0:
        if strict:
            binascii.a2b_base64(data, strict_mode=True)
        else:
            binascii.a2b_base64(data)
    elif which == 1:
        binascii.a2b_hex(data)
    elif which == 2:
        binascii.a2b_uu(data)
    elif which == 3:
        binascii.a2b_qp(data)
    elif which == 4:
        binascii.a2b_base64(data)
    elif which == 5:
        binascii.a2b_base64(data)

def op_encode(fdp):
    which = fdp.ConsumeIntInRange(0, 5)
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
    if n == 0:
        return
    data = fdp.ConsumeBytes(n)
    if which == 0:
        newline = fdp.ConsumeBool()
        binascii.b2a_base64(data, newline=newline)
    elif which == 1:
        binascii.b2a_hex(data)
    elif which == 2:
        binascii.b2a_uu(data[:45])
    elif which == 3:
        binascii.b2a_qp(data)
    elif which == 4:
        binascii.b2a_base64(data)
    elif which == 5:
        binascii.b2a_base64(data)

def op_checksum(fdp):
    use_crc32 = fdp.ConsumeBool()
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    if use_crc32:
        binascii.crc32(data)
    else:
        binascii.crc_hqx(data, 0)

def op_roundtrip(fdp):
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    hexed = binascii.hexlify(data)
    binascii.unhexlify(hexed)

def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x100000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    op = fdp.ConsumeIntInRange(0, 3)
    try:
        if op == 0:
            op_decode(fdp)
        elif op == 1:
            op_encode(fdp)
        elif op == 2:
            op_checksum(fdp)
        else:
            op_roundtrip(fdp)
    except Exception:
        pass
